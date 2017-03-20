'use strict';

require('isomorphic-fetch');
const _ = require('lodash');
const crypto = require('crypto');
const Promise = require('bluebird');
const qs = require('querystring');
const Type = require('./types');

Promise.config({
    longStackTraces: true
});

function getMetadata(data) {
    return data[_.keys(data)[0]].ResponseMetadata;
}

class AmazonMwsClient {
    /**
     * Constructor for the main MWS client interface used to make api calls and
     * various data structures to encapsulate MWS requests, definitions, etc.
     *
     * @param {Object} options         configuration options for this instance
     */
    constructor(options) {
        const opts = _.defaultsDeep(options || {}, {
            host: 'mws.amazonservices.com',
            appName: 'mws-api',
            appVersion: '0.1.0',
            appLanguage: 'JavaScript',
            meta: {
                retry: true,
                next: false,
                limit: Infinity,
                max_backoff: 10000,
                max_attempts: Infinity,
                attempt: -1,
                contentType: 'application/x-www-form-urlencoded',
                parseCSVResult: (data) => data
            }
        });

        if (!opts.accessKeyId || !opts.secretAccessKey || !opts.merchantId) {
            const missing = _.keys(_.pickBy({
                accessKeyId: opts.accessKeyId,
                secretAccessKey: opts.secretAccessKey,
                merchantId: opts.merchantId
            }, _.negate(_.identity)));

            throw new Error(`Missing Amazon client parameter${missing.length > 2 ? 's' : ''}: ${missing.join(', ')}!`);
        }

        this.host = opts.host;
        this.appName = opts.appName;
        this.appVersion = opts.appVersion;
        this.appLanguage = opts.appLanguage;
        this.accessKeyId = opts.accessKeyId;
        this.secretAccessKey = opts.secretAccessKey;
        this.merchantId = opts.merchantId;
        this.authToken = opts.authToken;
        this.meta = opts.meta;

        _.merge(this, require('./api')(this));
    }

    request(req, q, meta) {
        const api = req.api;
        const action = req.action;
        const uri = `https://${this.host}${api.path}`;
        const requestOpts = {};
        const query = _.clone(q);

        if (api.upload) {
          return
        }

        const headers = {
            'Host': this.host,
            'User-Agent': `${this.appName}/${this.appVersion} (Language=${this.appLanguage})`,
            'Content-Type': 'application/x-www-form-urlencoded'
        };

        const body = _.findKey(req.params, { type: Type.BODY });

        // Add required parameters and sign the query
        query.Action = action;
        query.Version = api.version;
        query.Timestamp = new Date().toISOString();
        query.AWSAccessKeyId = this.accessKeyId;

        if (this.authToken) {
            query.MWSAuthToken = this.authToken;
        }

        query[api.legacy ? 'Merchant' : 'SellerId'] = this.merchantId;

        const signedQuery = this.sign(api.path, _.omit(query, body));
        requestOpts.body = qs.stringify(signedQuery);
        requestOpts.headers = headers;
        requestOpts.method = 'POST';
        const uriQuery = qs.stringify(query)

        return fetch(uri, requestOpts)
    }

    /**
     * The method used to invoke calls against MWS Endpoints. Recommended usage is
     * through the invoke wrapper method when the api call you're invoking has a
     * request defined in one of the submodules. However, you can use call() manually
     * when a lower level of control is necessary (custom or new requests, for example).
     *
     * @param  {Object}   api      Settings object unique to each API submodule
     * @param  {String}   action   Api `Action`, such as GetServiceStatus or GetOrder
     * @param  {Object}   query    Any parameters belonging to the current action
     * @return Promise
     */
    call(req, q, meta) {
      return this.request(req, q, meta)
        .then((response) => {
          if (!response.ok) {
            throw new Error(`Error ${response.status} making MWS request`)
          }

          return response.text()
        })
    }

    /**
     * Calculates the HmacSHA256 signature and appends it with additional signature
     * parameters to the provided query object.
     *
     * @param  {String} path  Path of API call (used to build the string to sign)
     * @param  {Object} query Any non-signature parameters that will be sent
     * @return {Object}       Finalized object used to build query string of request
     */
    sign(path, query) {
        query.SignatureMethod = 'HmacSHA256';
        query.SignatureVersion = '2';

        // Copy query keys, sort them, then copy over the values
        const sorted = _.reduce(_.keys(query).sort(), function (m, k) {
            m[k] = query[k];

            return m;
        }, {});

        const stringToSign = ['POST', this.host, path, qs.stringify(sorted)]
            .join('\n')
            .replace(/'/g, '%27')
            .replace(/\*/g, '%2A')
            .replace(/\(/g, '%28')
            .replace(/\)/g, '%29');

        return _.assign({}, query, {
            Signature: crypto.createHmac('sha256', this.secretAccessKey)
                .update(stringToSign, 'utf8')
                .digest('base64')
        });
    }

    /**
     * Suggested method for invoking a pre-defined mws request object.
     *
     * @param  {Object}   req  An instance of AmazonMwsRequest with params, etc.
     * @param  {Object}   meta     Metadata to determine how to handle the request.
     * @return Promise
     */
    invoke(req, meta) {
        return req.query().then((q) => this.call(req, q, _.defaults(meta, this.meta)));
    }
}

module.exports = AmazonMwsClient;
