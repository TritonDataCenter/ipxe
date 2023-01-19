/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright 2021 Joyent, Inc.
 * Copyright 2023 MNX Cloud, Inc.
 */

@Library('jenkins-joylib@v1.0.8') _

pipeline {

    agent {
        label joyCommonLabels(image_ver: '21.4.0')
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '30'))
        timestamps()
    }

    stages {
        stage('check') {
            steps{
                sh('make check')
            }
        }
        stage('build image and upload') {
            steps {
                sh('''
set -o errexit
set -o pipefail

export ENGBLD_BITS_UPLOAD_IMGAPI=true
make print-BRANCH print-STAMP all release publish bits-upload''')
            }
        }
    }

    post {
        always {
            joySlackNotifications(channel: 'jenkins')
        }
    }

}
