pipeline {
    agent {
        node {
            label params.SLAVE
        }
    }
    parameters {
        string(name: 'SETTINGS_CONFIG_FILE_NAME', defaultValue: 'maven.settings.eso')
        string(name: 'ARMDOCKER_CONFIG_FILE_NAME', defaultValue: 'armdocker.login.config')
        string(name: 'BOB2_VERSION', defaultValue: '1.7.0-5')
        string(name: 'NEW_BASE_IMAGE_VERSION', defaultValue: '')
        string(name: 'JOB_NAME_TO_TRIGGER', defaultValue: 'eric-esoa-so_Release')
    }
    environment {
        GIT_URL = "${env.GERRIT_CENTRAL}/ESOA/ESOA-Parent/com.ericsson.bos.so/eric-esoa-so-iam-client"
    }

    stages {

        stage('Prepare Bob') {
            steps {
                script{
                    def envMap = readProperties(text: sh(script: 'env', returnStdout: true).trim())
                    def bobCommand = load 'bobContainerConfig'
                    bob2 = bobCommand.createCommandWithEnv(envMap)
                }
            }
        }

        stage('Inject Settings.xml File') {
            steps {
                configFileProvider([configFile(fileId: "${env.SETTINGS_CONFIG_FILE_NAME}", targetLocation: "${env.WORKSPACE}")]) {
                }
                // Inject docker config json
                configFileProvider([configFile(fileId: "${env.ARMDOCKER_CONFIG_FILE_NAME}", targetLocation: "${env.WORKSPACE}/.docker/")]) {
                }
            }
        }


        stage("Retrieve current base image version") {
            steps {
                script {
                    env.CURRENTVERSION = sh(script: 'grep -Eo \'^FROM .*:.*\' Dockerfile | sed \'s/.*://; s/ as.*//\'',
                    returnStdout:true)
                    NEW_BASE_IMAGE_VERSION = NEW_BASE_IMAGE_VERSION.replaceAll("\"", "");
                    echo "Current base image version is ${CURRENTVERSION}"
                    echo "Requested update to version: ${NEW_BASE_IMAGE_VERSION}"

                    env.UPDATING_BASE_OS_VERSION = 'false'
                        if (env.NEW_BASE_IMAGE_VERSION != null && env.NEW_BASE_IMAGE_VERSION.trim().length() != 0 &&
                         !env.CURRENTVERSION.toString().trim().equals(NEW_BASE_IMAGE_VERSION)) {
                            env.UPDATING_BASE_OS_VERSION = 'true'
                            echo "Update to base image required new CBO version detected"
                            echo "Updating base image to version: ${NEW_BASE_IMAGE_VERSION}"
                        } else {
                            echo "No update to base image required"
                        }
                }
            }
        }

        stage("Check files in commit") {
            steps {
                script {
                  env.BUILD_AND_RELEASE_IMAGE='false'
                  def dockerfile = "Dockerfile"
                  def scripts = "keycloak_client/scripts/"
                  def entrypoint = "keycloak_client/entrypoint.sh"

                  def filesInCommit= sh(returnStdout: true, script: "git diff --name-only HEAD^ HEAD")
                  if( (filesInCommit.contains(dockerfile) && UPDATING_BASE_OS_VERSION.equals('false'))
                      || filesInCommit.contains(scripts)
                      || filesInCommit.contains(entrypoint)
                      || UPDATING_BASE_OS_VERSION.equals('true') ) {
                    env.BUILD_AND_RELEASE_IMAGE='true'
                  }
                  echo "This commit will build and release a new image = ${env.BUILD_AND_RELEASE_IMAGE}"
                }
            }
        }

        stage('Clean') {
            steps {
                sh "${bob2} clean"
            }
        }

        stage('Update Version') {
           when { environment name: "UPDATING_BASE_OS_VERSION", value: 'true' }
           steps {
               script {
               sh 'sed -i \"s#' + CURRENTVERSION.trim() + '#'+ NEW_BASE_IMAGE_VERSION +'#\" Dockerfile'

               def versionAfterUpdate = sh(script: 'grep -Eo \'^FROM .*:.*\' Dockerfile | sed \'s/.*://; s/ as.*//\'',
               returnStdout:true)

               echo "Keycloak Client dockerfile updated successfully to new base image version: ${versionAfterUpdate}"
               }
           }
        }

        stage('Commit Dockerfile changes') {
            when { environment name: "UPDATING_BASE_OS_VERSION", value: 'true' }
            steps {
              sh "git remote set-url --push origin ${env.GIT_URL}"
              sh('''
                    git status;
                    git add Dockerfile;
                    git commit -m "Incrementing base image version to ${NEW_BASE_IMAGE_VERSION}";
                    git push origin HEAD:master;
                ''')
            }
        }

        stage('Init') {
            steps {
                sh "${bob2} init"
                sh "echo IMAGE_RELEASED=${env.BUILD_AND_RELEASE_IMAGE} >> artifact.properties"
                archiveArtifacts 'artifact.properties'
            }
        }

        stage('Tests') {
            //Both pyLint and pyTests are running in this single stage now
            steps {
                script {
                    sh "${bob2} test"
                }
            }
        }

       stage('Build image') {
            when { environment name: "BUILD_AND_RELEASE_IMAGE", value: 'true' }
            steps {
                script {
                    sh "${bob2} image"
                }
            }
        }

        stage('Push image') {
            when {
              allOf{
                  expression { params.RELEASE == "true" }
                  environment(name: "BUILD_AND_RELEASE_IMAGE", value: 'true')
              }
            }
            steps {
                sh "${bob2} package"
            }
        }
    }
}