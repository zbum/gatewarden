pipeline {
    agent none

    parameters {
        string(name: 'UBUNTU_BUILD_NODE_LABEL', defaultValue: 'linux && amd64 && ubuntu-build', description: 'Ubuntu amd64 node with Go, make, and Docker')
        string(name: 'ROCKY_BUILD_NODE_LABEL', defaultValue: 'linux && amd64 && rocky-build', description: 'Rocky amd64 node with Go, make, and Docker')
        string(name: 'NEXUS_CREDENTIALS_ID', defaultValue: 'nexus-credentials', description: 'Jenkins username/password credential for release publishing')
    }

    options {
        disableConcurrentBuilds()
        skipDefaultCheckout(true)
        timestamps()
        timeout(time: 30, unit: 'MINUTES')
    }

    stages {
        stage('Test and build packages') {
            parallel {
                stage('Ubuntu deb') {
                    agent { label "${params.UBUNTU_BUILD_NODE_LABEL}" }
                    steps {
                        checkout scm
                        sh 'for tool in git go make docker file; do command -v "$tool"; done'
                        script {
                            if (env.BRANCH_NAME?.startsWith('release/')) {
                                def branchVersion = env.BRANCH_NAME.substring('release/'.length())
                                def releaseVersion = readFile('VERSION').trim()
                                if (releaseVersion != branchVersion) {
                                    error("release branch ${env.BRANCH_NAME} does not match VERSION ${releaseVersion}")
                                }
                                currentBuild.displayName = "#${env.BUILD_NUMBER} v${releaseVersion}"
                            }
                        }
                        sh 'make package-image-deb'
                        sh 'make check'
                        sh 'make deb'
                        sh 'make checksums'
                        sh 'file dist/gatewarden-linux-amd64 dist/deb/*.deb'
                        stash name: 'ubuntu-deb-package', includes: 'dist/deb/**,scripts/publish-deb.sh', useDefaultExcludes: false
                        archiveArtifacts artifacts: 'dist/gatewarden-linux-amd64,dist/SHA256SUMS,dist/deb/**', fingerprint: true
                    }
                }
                stage('Rocky RPM') {
                    agent { label "${params.ROCKY_BUILD_NODE_LABEL}" }
                    steps {
                        checkout scm
                        sh 'for tool in git go make docker file; do command -v "$tool"; done'
                        sh 'make package-image-rpm'
                        sh 'make check'
                        sh 'make rpm'
                        sh 'file dist/gatewarden-linux-amd64 dist/rpm/*.rpm'
                        stash name: 'rocky-rpm-package', includes: 'dist/rpm/**,scripts/publish-rpm.sh', useDefaultExcludes: false
                        archiveArtifacts artifacts: 'dist/rpm/**', fingerprint: true
                    }
                }
            }
        }

        stage('Publish release packages') {
            when {
                beforeAgent true
                expression { env.BRANCH_NAME?.startsWith('release/') }
            }
            parallel {
                stage('Publish deb') {
                    agent { label "${params.UBUNTU_BUILD_NODE_LABEL}" }
                    steps {
                        deleteDir()
                        unstash 'ubuntu-deb-package'
                        withCredentials([usernamePassword(credentialsId: params.NEXUS_CREDENTIALS_ID, usernameVariable: 'NEXUS_USER', passwordVariable: 'NEXUS_PASS')]) {
                            sh 'SKIP_PACKAGE_BUILD=1 ./scripts/publish-deb.sh'
                        }
                    }
                }
                stage('Publish RPM') {
                    agent { label "${params.ROCKY_BUILD_NODE_LABEL}" }
                    steps {
                        deleteDir()
                        unstash 'rocky-rpm-package'
                        withCredentials([usernamePassword(credentialsId: params.NEXUS_CREDENTIALS_ID, usernameVariable: 'NEXUS_USER', passwordVariable: 'NEXUS_PASS')]) {
                            sh 'SKIP_PACKAGE_BUILD=1 ./scripts/publish-rpm.sh'
                        }
                    }
                }
            }
        }
    }
}
