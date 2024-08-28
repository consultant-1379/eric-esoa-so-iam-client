##################################################################################
FROM armdocker.rnd.ericsson.se/proj-ldc/common_base_os/sles:6.17.0-11 as base_image

RUN zypper ar -C -G -f https://arm.rnd.ki.sw.ericsson.se/artifactory/proj-ldc-repo-rpm-local/common_base_os/sles/6.17.0-11?ssl_verify=no LDC-CBO-SLES \
 && zypper ref -f -r LDC-CBO-SLES \
    && zypper install -l -y python311 \
                            python311-pip \
                            iputils \
    && update-alternatives --install /usr/bin/python python /usr/bin/python3.11 1 \
    && update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1 \
    && python -m pip install --disable-pip-version-check --no-cache-dir \
                                        --trusted-host pypi.org retrying==1.3.4 \
                                                                cryptography==42.0.4 \
                                                                certifi==2023.11.17 \
                                                                requests==2.31.0 \
                                                                urllib3==2.1.0

COPY keycloak_client /keycloak_client

# User Id generated based on ADP rule DR-D1123-122 (keycloak-client : 128474)
ARG uid=128474
ARG gid=128474

RUN echo "${uid}:x:${uid}:${gid}:keycloak-user:/:/bin/false" >> /etc/passwd \
    && sed -i '/root/s/bash/false/g' /etc/passwd \
    && zypper addrepo -C -G -f https://arm.sero.gic.ericsson.se/artifactory/proj-ldc-repo-rpm-local/common_base_os/sles/6.17.0-11?ssl_verify=no COMMON_BASE_OS_SLES_REPO \
    && zypper install -l -y curl \
    && zypper clean --all \
    && chown ${uid}:0 /var/lib/ca-certificates/ca-bundle.pem \
    && chown ${uid}:0 /etc/ssl/ca-bundle.pem \
    && chmod -R g=u /var/lib/ca-certificates/ca-bundle.pem \
    && chmod -R g=u /etc/ssl/ca-bundle.pem \
    && chmod 755 /etc/ssl/ca-bundle.pem \
    && chown ${uid}:0 /keycloak_client \
    && chmod -R g=u /keycloak_client


##################################################################################
FROM base_image as release_image

RUN zypper remove -y python311-pip \
    && zypper clean --all

RUN rm -rf /keycloak_client/tests

ARG uid=128474
ARG gid=128474
USER ${uid}:${gid}

ENTRYPOINT ["/keycloak_client/entrypoint.sh"]

##################################################################################
FROM base_image as test_image

RUN pip install --no-cache-dir --trusted-host pypi.org \
            pytest==7.4.3  \
            pylint==3.0.3

USER ${uid}:${gid}

#Run lint
RUN pylint --max-line-length=120 --disable=C0209 \
                                 --disable=R0022 \
                                 --disable=W0707 \
                                 --disable=W0719 \
                                 --disable=W1514 \
                                 --disable=W3101 \
                                    /keycloak_client

#Run unit tests
RUN pytest /keycloak_client -v

##################################################################################

