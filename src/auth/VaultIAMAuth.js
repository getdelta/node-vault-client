'use strict';

const VaultBaseAuth = require('./VaultBaseAuth');
const { SignatureV4 } = require('@aws-sdk/signature-v4');
const { Hash } = require('@aws-sdk/hash-node');
const _ = require('lodash');

/**
 * Implementation of AWS Auth Backend :: IAM Authentication Method
 * @link https://www.vaultproject.io/docs/auth/aws.html#iam-authentication-method
 *
 * @usage
 *
 * ```bash
 * vault write auth/aws/config/client secret_key=AWS_SECRET_KEY access_key=AWS_ACCESS_KEY
 * vault write auth/aws/config/client iam_server_id_header_value=VAULT_ADDR
 * vault write auth/aws/role/iam_name_of_role auth_type=iam bound_iam_principal_arn=arn:aws:iam::.... max_ttl=500h
 * ```
 *
 * ```js
 *
 * VaultClient.boot('main', {
 *       api: { url: VAULT_ADDR },
 *       auth: {
 *           type: 'iam',
 *           mount: 'some_other_aws_mount_point',          // Optional
 *           config: {
 *               role: 'my_iam_role',
 *               iam_server_id_header_value: VAULT_ADDR,   // Optional
 *               region: AWS_REGION,
 *               credentials: {
 *                 accessKeyId: AWS_ACCESS_KEY,
 *                 secretAccessKey: AWS_SECRET_KEY,
 *               }
 *           }
 *       }
 *   })
 *
 * ```
 *
 */
class VaultIAMAuth extends VaultBaseAuth {
    /**
     * @param {VaultApiClient} api - see {@link VaultBaseAuth#constructor}
     * @param {Object} logger
     * @param {Object} config
     * @param {String} config.role - Role name of the auth/{mount}/role/{name} backend.
     * @param {AWS.Credentials|AWS.CredentialProvider|undefined} config.credentials {@see AWS.CredentialProviderChain providers}
     * @param {String} config.region AWS region, used when talking to STS
     * @param {String} [config.iam_server_id_header_value] - Optional. Header's value X-Vault-AWS-IAM-Server-ID.
     * @param {String} mount - Vault's AWS Auth Backend mount point ("aws" by default)
     */
    constructor(api, logger, config, mount) {
        super(api, logger, mount || 'aws');

        this.__role = config.role;
        this.__iam_server_id_header_value = config.iam_server_id_header_value;
        this.__signer = new SignatureV4({
            credentials: config.credentials || require('@aws-sdk/credential-provider-node').defaultProvider(),
            region: config.region,
            service: 'sts',
            sha256: Hash.bind(null, "sha256")
        });
    }

    /**
     * @inheritDoc
     */
    _authenticate() {
        this._log.info(
            'making authentication request: role=%s',
            this.__role
        );

        return Promise.resolve()
            .then((credentials) => this.__getStsRequest(credentials))
            .then((sts_request) => {
                return this.__apiClient.makeRequest(
                    'POST',
                    `/auth/${this._mount}/login`,
                    this.__getVaultAuthRequestBody(sts_request)
                );
            })
            .then((response) => {
                this._log.debug(
                    'receive token: %s',
                    response.auth.client_token
                );
                return this._getTokenEntity(response.auth.client_token)
            })
    }

    /**
     * Prepare vault auth request body
     *
     * @param stsRequest
     * @returns {Object} {@link https://www.vaultproject.io/docs/auth/aws.html#via-the-api}
     * @private
     */
    __getVaultAuthRequestBody(stsRequest) {
        return {
            iam_http_request_method: stsRequest.method,
            iam_request_headers: this.__base64encode(
                JSON.stringify(this.__headersLikeGolangStyle(stsRequest.headers))
            ),
            iam_request_body: this.__base64encode(stsRequest.body),
            iam_request_url: this.__base64encode(`${stsRequest.protocol}://${stsRequest.hostname}${stsRequest.path}`),
            role: this.__role
        }
    }

    /**
     * Prepare signed request to AWS STS :: GetCallerIdentity
     *
     * @private
     */
    __getStsRequest() {
        const body = 'Action=GetCallerIdentity&Version=2011-06-15';
        const headers = {
            'host': 'sts.amazonaws.com',
            'content-type': 'application/x-www-form-urlencoded; charset=utf-8',
            'content-length': body.length.toString(),
        };
        if (this.__iam_server_id_header_value) {
            headers['x-vault-aws-iam-server-id'] = this.__iam_server_id_header_value;
        }

        return this.__signer.sign({
            method: 'POST',
            body,
            headers,
            path: '/',
            hostname: 'sts.amazonaws.com',
            protocol: 'https',
        });
    }

    /**
     * @param string
     * @private
     */
    __base64encode(string) {
        return Buffer.from(string, 'utf8').toString('base64');
    }

    /**
     * @link https://github.com/hashicorp/vault/issues/2810
     * @link https://golang.org/pkg/net/http/#Header
     *
     * @param {Object} headers
     * @returns {Object}
     * @private
     */
    __headersLikeGolangStyle(headers) {
        return _.mapValues(headers, (value) => [`${value}`]);
    }
}

module.exports = VaultIAMAuth;
