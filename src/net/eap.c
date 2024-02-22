/*
 * Copyright (C) 2021 Michael Brown <mbrown@fensystems.co.uk>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * You can also choose to distribute this program under the terms of
 * the Unmodified Binary Distribution Licence (as given in the file
 * COPYING.UBDL), provided that you have satisfied its requirements.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <byteswap.h>
#include <ipxe/netdevice.h>
#include <ipxe/md5.h>
#include <ipxe/chap.h>
#include <ipxe/eap.h>

/** @file
 *
 * Extensible Authentication Protocol
 *
 */

/**
 * Transmit EAP response
 *
 * @v supplicant	EAP supplicant
 * @v rsp		Response type data
 * @v rsp_len		Length of response type data
 * @ret rc		Return status code
 */
static int eap_tx_response ( struct eap_supplicant *supplicant,
			     const void *rsp, size_t rsp_len ) {
	struct net_device *netdev = supplicant->netdev;
	struct eap_message *msg;
	size_t len;
	int rc;

	/* Allocate and populate response */
	len = ( sizeof ( *msg ) + rsp_len );
	msg = malloc ( len );
	if ( ! msg ) {
		rc = -ENOMEM;
		goto err_alloc;
	}
	msg->hdr.code = EAP_CODE_RESPONSE;
	msg->hdr.id = supplicant->id;
	msg->hdr.len = htons ( len );
	msg->type = supplicant->type;
	memcpy ( msg->data, rsp, rsp_len );

	/* Transmit response */
	if ( ( rc = supplicant->tx ( supplicant, msg, len ) ) != 0 ) {
		DBGC ( netdev, "EAP %s could not transmit: %s\n",
		       netdev->name, strerror ( rc ) );
		goto err_tx;
	}

 err_tx:
	free ( msg );
 err_alloc:
	return rc;
}

/**
 * Transmit EAP NAK
 *
 * @v supplicant	EAP supplicant
 * @ret rc		Return status code
 */
static int eap_tx_nak ( struct eap_supplicant *supplicant ) {
	unsigned int max = table_num_entries ( EAP_METHODS );
	uint8_t methods[ max + 1 /* potential EAP_TYPE_NONE */ ];
	unsigned int count = 0;
	struct eap_method *method;

	/* Populate methods list */
	for_each_table_entry ( method, EAP_METHODS ) {
		if ( method->type > EAP_TYPE_NAK )
			methods[count++] = method->type;
	}
	if ( ! count )
		methods[count++] = EAP_TYPE_NONE;
	assert ( count <= max );

	/* Transmit response */
	supplicant->type = EAP_TYPE_NAK;
	return eap_tx_response ( supplicant, methods, count );
}

/**
 * Handle EAP Request-Identity
 *
 * @v supplicant	EAP supplicant
 * @v req		Request type data
 * @v req_len		Length of request type data
 * @ret rc		Return status code
 */
static int eap_rx_identity ( struct eap_supplicant *supplicant,
			     const void *req, size_t req_len ) {
	struct net_device *netdev = supplicant->netdev;
	void *rsp;
	int rsp_len;
	int rc;

	/* Treat Request-Identity as blocking the link */
	DBGC ( netdev, "EAP %s Request-Identity blocking link\n",
	       netdev->name );
	DBGC_HDA ( netdev, 0, req, req_len );
	netdev_link_block ( netdev, EAP_BLOCK_TIMEOUT );

	/* Mark EAP as in progress */
	supplicant->flags |= EAP_FL_ONGOING;

	/* Construct response, if applicable */
	rsp_len = fetch_raw_setting_copy ( netdev_settings ( netdev ),
					   &username_setting, &rsp );
	if ( rsp_len < 0 ) {
		/* We have no identity to offer, so wait until the
		 * switch times out and switches to MAC Authentication
		 * Bypass (MAB).
		 */
		DBGC2 ( netdev, "EAP %s has no identity\n", netdev->name );
		supplicant->flags |= EAP_FL_PASSIVE;
		rc = 0;
		goto no_response;
	}

	/* Transmit response */
	if ( ( rc = eap_tx_response ( supplicant, rsp, rsp_len ) ) != 0 )
		goto err_tx;

 err_tx:
	free ( rsp );
 no_response:
	return rc;
}

/** EAP Request-Identity method */
struct eap_method eap_identity_method __eap_method = {
	.type = EAP_TYPE_IDENTITY,
	.rx = eap_rx_identity,
};

/**
 * Handle EAP MD5-Challenge
 *
 * @v req		Request type data
 * @v req_len		Length of request type data
 * @ret rc		Return status code
 */
static int eap_rx_md5 ( struct eap_supplicant *supplicant,
			const void *req, size_t req_len ) {
	struct net_device *netdev = supplicant->netdev;
	const struct eap_md5 *md5req = req;
	struct {
		uint8_t len;
		uint8_t value[MD5_DIGEST_SIZE];
	} __attribute__ (( packed )) md5rsp;
	struct chap_response chap;
	void *secret;
	int secret_len;
	int rc;

	/* Sanity checks */
	if ( req_len < sizeof ( *md5req ) ) {
		DBGC ( netdev, "EAP %s underlength MD5-Challenge:\n",
		       netdev->name );
		DBGC_HDA ( netdev, 0, req, req_len );
		rc = -EINVAL;
		goto err_sanity;
	}
	if ( ( req_len - sizeof ( *md5req ) ) < md5req->len ) {
		DBGC ( netdev, "EAP %s truncated MD5-Challenge:\n",
		       netdev->name );
		DBGC_HDA ( netdev, 0, req, req_len );
		rc = -EINVAL;
		goto err_sanity;
	}

	/* Construct response */
	if ( ( rc = chap_init ( &chap, &md5_algorithm ) ) != 0 ) {
		DBGC ( netdev, "EAP %s could not initialise CHAP: %s\n",
		       netdev->name, strerror ( rc ) );
		goto err_chap;
	}
	chap_set_identifier ( &chap, supplicant->id );
	secret_len = fetch_raw_setting_copy ( netdev_settings ( netdev ),
					      &password_setting, &secret );
	if ( secret_len < 0 ) {
		rc = secret_len;
		DBGC ( netdev, "EAP %s has no secret: %s\n",
		       netdev->name, strerror ( rc ) );
		goto err_secret;
	}
	chap_update ( &chap, secret, secret_len );
	chap_update ( &chap, md5req->value, md5req->len );
	chap_respond ( &chap );
	assert ( chap.response_len == sizeof ( md5rsp.value ) );
	md5rsp.len = sizeof ( md5rsp.value );
	memcpy ( md5rsp.value, chap.response, sizeof ( md5rsp.value ) );

	/* Transmit response */
	if ( ( rc = eap_tx_response ( supplicant, &md5rsp,
				      sizeof ( md5rsp ) ) ) != 0 )
		goto err_tx;

 err_tx:
	free ( secret );
 err_secret:
	chap_finish ( &chap );
 err_chap:
 err_sanity:
	return rc;
}

/** EAP MD5-Challenge method */
struct eap_method eap_md5_method __eap_method = {
	.type = EAP_TYPE_MD5,
	.rx = eap_rx_md5,
};

/**
 * Handle EAP Request
 *
 * @v supplicant	EAP supplicant
 * @v msg		EAP request
 * @v len		Length of EAP request
 * @ret rc		Return status code
 */
static int eap_rx_request ( struct eap_supplicant *supplicant,
			    const struct eap_message *msg, size_t len ) {
	struct net_device *netdev = supplicant->netdev;
	struct eap_method *method;
	const void *req;
	size_t req_len;

	/* Sanity checks */
	if ( len < sizeof ( *msg ) ) {
		DBGC ( netdev, "EAP %s underlength request:\n", netdev->name );
		DBGC_HDA ( netdev, 0, msg, len );
		return -EINVAL;
	}
	if ( len < ntohs ( msg->hdr.len ) ) {
		DBGC ( netdev, "EAP %s truncated request:\n", netdev->name );
		DBGC_HDA ( netdev, 0, msg, len );
		return -EINVAL;
	}
	req = msg->data;
	req_len = ( ntohs ( msg->hdr.len ) - sizeof ( *msg ) );

	/* Record request details */
	supplicant->id = msg->hdr.id;
	supplicant->type = msg->type;

	/* Handle according to type */
	for_each_table_entry ( method, EAP_METHODS ) {
		if ( msg->type == method->type )
			return method->rx ( supplicant, req, req_len );
	}
	DBGC ( netdev, "EAP %s requested type %d unknown:\n",
	       netdev->name, msg->type );
	DBGC_HDA ( netdev, 0, msg, len );

	/* Send NAK if applicable */
	if ( msg->type > EAP_TYPE_NAK )
		return eap_tx_nak ( supplicant );

	return -ENOTSUP;
}

/**
 * Handle EAP Success
 *
 * @v supplicant	EAP supplicant
 * @ret rc		Return status code
 */
static int eap_rx_success ( struct eap_supplicant *supplicant ) {
	struct net_device *netdev = supplicant->netdev;

	/* Mark authentication as complete */
	supplicant->flags = EAP_FL_PASSIVE;

	/* Mark link as unblocked */
	DBGC ( netdev, "EAP %s Success\n", netdev->name );
	netdev_link_unblock ( netdev );

	return 0;
}

/**
 * Handle EAP Failure
 *
 * @v supplicant	EAP supplicant
 * @ret rc		Return status code
 */
static int eap_rx_failure ( struct eap_supplicant *supplicant ) {
	struct net_device *netdev = supplicant->netdev;

	/* Mark authentication as complete */
	supplicant->flags = EAP_FL_PASSIVE;

	/* Record error */
	DBGC ( netdev, "EAP %s Failure\n", netdev->name );
	return -EPERM;
}

/**
 * Handle EAP packet
 *
 * @v supplicant	EAP supplicant
 * @v data		EAP packet
 * @v len		Length of EAP packet
 * @ret rc		Return status code
 */
int eap_rx ( struct eap_supplicant *supplicant, const void *data,
	     size_t len ) {
	struct net_device *netdev = supplicant->netdev;
	const union eap_packet *eap = data;

	/* Sanity check */
	if ( len < sizeof ( eap->hdr ) ) {
		DBGC ( netdev, "EAP %s underlength header:\n", netdev->name );
		DBGC_HDA ( netdev, 0, eap, len );
		return -EINVAL;
	}

	/* Handle according to code */
	switch ( eap->hdr.code ) {
	case EAP_CODE_REQUEST:
		return eap_rx_request ( supplicant, &eap->msg, len );
	case EAP_CODE_RESPONSE:
		DBGC2 ( netdev, "EAP %s ignoring response\n", netdev->name );
		return 0;
	case EAP_CODE_SUCCESS:
		return eap_rx_success ( supplicant );
	case EAP_CODE_FAILURE:
		return eap_rx_failure ( supplicant );
	default:
		DBGC ( netdev, "EAP %s unsupported code %d\n",
		       netdev->name, eap->hdr.code );
		DBGC_HDA ( netdev, 0, eap, len );
		return -ENOTSUP;
	}
}
