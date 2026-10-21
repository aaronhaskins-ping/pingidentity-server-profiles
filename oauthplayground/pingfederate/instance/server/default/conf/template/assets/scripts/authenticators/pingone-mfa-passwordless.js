const PasswordlessAuthenticator = {
    assertionResponse: undefined,
    abortController: null,
    abortSignal: null,
    webauthnOptions: null,
    environmentId: null,
    mediation: null,
    desktopOptions: null,
    desktopPort: null,
    desktopRpId: null,
    usernamelessButtonLabel: null,
    usernamelessAllowed: false,
    origin: null,
    usernamelessAssertionFieldName: "usernameless-assertion",

    addHiddenInput(name, value) {
        if (value) {
            let input = document.createElement("input");
            input.setAttribute("type", "hidden");
            input.setAttribute("name", name);
            input.setAttribute("value", value);
            document.getElementsByTagName("form")[0].appendChild(input);
        }
    },

    isSafari() {
        const { userAgent, userAgentData } = navigator;
        // Check for Safari (but not Chrome or other WebKit browsers)
        const isSafari = /^((?!chrome|android|crios|fxios|edgios).)*safari/i.test(userAgent);

        // Prefer userAgentData if available
        if (userAgentData) {
            const platform = userAgentData.platform || '';
            return isSafari && platform.toLowerCase().includes('mac');
        }

        // Fallback for older Safari (if Safari doesn't support userAgentData)
        return isSafari && /Macintosh|MacIntel|MacPPC|Mac68K/.test(userAgent);
    },

    getSSOExtensionUrl() {
        const fullHost = window.location.hostname;
        return `https://${fullHost}/pingid/desktop`;
    },

    async isDesktopAppAvailable(port, environmentId, rpId) {
        if (port == null || environmentId == null || rpId == null) {
            return false;
        }

        try {
            const response = await fetch(`http://127.0.0.1:${port}/status?environmentId=${environmentId}&rpId=${rpId}`);
            if (!response.ok) {
                return false;
            }
            const body = await response.json();
            return body['registered']
        } catch (e) {
            console.error('Error fetching PingID Desktop status:', e);
            return false;
        }
    },

    async shouldAuthenticateWithDesktop(port, environmentId, rpId, desktopRequestOptions) {
        if (desktopRequestOptions == null) {
            return false;
        }

        return this.isSafari() || await this.isDesktopAppAvailable(port, environmentId, rpId);
    },

    async authenticateViaSSOExtension(desktopRequestOptions) {
        console.debug("Initiating SSO Extension flow");
        const baseUrl = `${this.getSSOExtensionUrl()}/authenticate`;
        const url = new URL(baseUrl);
        const redirectUri = new URL(window.location.href);

        // Clean up current URL
        redirectUri.searchParams.delete('auth_token');
        redirectUri.hash = '';

        // Set hash for callback
        redirectUri.hash = 'pingid_sso_callback';

        // Prepare the URL with parameters
        url.searchParams.set('redirect_uri', redirectUri.toString());
        url.searchParams.set('request', desktopRequestOptions);

        // Top-level navigation so the Redirect-type SSO extension will run
        window.top.location.assign(url.toString());
    },

    getSSOExtensionQueryParams() {
        if (window.location.hash && window.location.hash.startsWith('#pingid_sso_callback')) {
            const hash = window.location.hash;
            // Look for parameters after the first '?'
            const qIndex = hash.indexOf('?');
            if (qIndex !== -1) {
                // Normalize any subsequent '?' to '&' in case of bad appending, then parse
                const paramsString = hash.substring(qIndex + 1).replace(/\?/g, '&');
                const hashParams = new URLSearchParams(paramsString);

                const error = hashParams.get('error');
                if (error) {
                    console.error("SSO Extension returned error:", error);
                    // Sanitize hash
                    window.history.replaceState({}, document.title, window.location.pathname + window.location.search);
                    return { authToken: null, error: error };
                }

                const authToken = hashParams.get('auth_token');
                if (authToken) {
                    // Sanitize hash
                    window.history.replaceState({}, document.title, window.location.pathname + window.location.search);
                    return { authToken };
                }
            }
        }

        // Fallback to query params - shouldn't happen
        const queryParams = new URLSearchParams(window.location.search);
        const authToken = queryParams.get('auth_token');
        if (authToken) {
            // Sanitize query params
            const url = new URL(window.location.href);
            url.searchParams.delete('auth_token');
            window.history.replaceState({}, document.title, url.toString());
            return { authToken };
        }
        return { authToken: null };
    },

    async authenticateDesktop(port, desktopRequestOptions) {
        if (this.isSafari()) {
            return this.authenticateViaSSOExtension(desktopRequestOptions);
        }

        return fetch(`http://127.0.0.1:${port}/authenticate`, {
            method: 'POST',
            headers: {
                'Origin': this.origin,
                'Content-Type': 'application/jwt'
            },
            body: desktopRequestOptions
        }).then(res => {
            if (res.ok) {
                return res.text()
                    .then(jwt => jwt)
                    .catch(e => {
                        console.error("Failed getting PingID Desktop response body", e)
                        throw new Error(e);
                    });
            }
            throw new Error(`PingID Desktop authentication failed with status: ${res.status}`);
        }).catch(e => {
            console.error('Error authenticating with PingID Desktop:', e);
            throw new Error(e);
        });
    },

    credentialListConversion(list) {
        return list.map(item => {
            let cred = {
                type: item.type,
                id: new Uint8Array(item.id)
            };
            if (item.transports) cred.transports = item.transports;
            return cred;
        });
    },

    toBase64Str(bin) {
        return btoa(String.fromCharCode.apply(null, new Uint8Array(bin)));
    },

    prepareWebAuthnRequestOptions(webauthnRequestOptions) {
        let options = JSON.parse(webauthnRequestOptions);
        let publicKeyCredential = {
            challenge: new Uint8Array(options.challenge)
        };
        if ('allowCredentials' in options) {
            publicKeyCredential.allowCredentials = this.credentialListConversion(options.allowCredentials);
        }
        if ('rpId' in options) publicKeyCredential.rpId = options.rpId;
        if ('timeout' in options) publicKeyCredential.timeout = options.timeout;
        if ('userVerification' in options) publicKeyCredential.userVerification = options.userVerification;
        return publicKeyCredential;
    },

    parseWebAuthnAssertion(assertion) {
        let publicKeyCredential = {};
        if ('id' in assertion) publicKeyCredential.id = assertion.id;
        if ('rawId' in assertion) publicKeyCredential.rawId = this.toBase64Str(assertion.rawId);
        if ('type' in assertion) publicKeyCredential.type = assertion.type;
        if ('authenticatorAttachment' in assertion) publicKeyCredential.authenticatorAttachment = assertion.authenticatorAttachment;
        let response = {
            clientDataJSON: this.toBase64Str(assertion.response.clientDataJSON),
            authenticatorData: this.toBase64Str(assertion.response.authenticatorData),
            signature: this.toBase64Str(assertion.response.signature),
        };

        if (assertion.response.userHandle) {
            response.userHandle = this.toBase64Str(assertion.response.userHandle);
        }

        publicKeyCredential.response = response;
        return JSON.stringify(publicKeyCredential);
    },

    async authenticateWebAuthn(webauthnCredentialRequestOptions) {
        if (webauthnCredentialRequestOptions == null) {
            return null;
        }

        const webauthnCredential = this.prepareWebAuthnRequestOptions(webauthnCredentialRequestOptions);
        this.abortController.abort(); // Abort any ongoing conditional mediation
        this.abortController = new AbortController();
        this.abortSignal = this.abortController.signal;
        return navigator.credentials.get({ publicKey: webauthnCredential })
            .then(assertion => this.parseWebAuthnAssertion(assertion))
            .catch(err => {
                throw new Error(err.name);
            });
    },

    async usernamelessAuthenticate(desktopPort, environmentId, desktopRpId, desktopRequestOptions, webauthnCredentialRequestOptions) {
        if (await this.shouldAuthenticateWithDesktop(desktopPort, environmentId, desktopRpId, desktopRequestOptions)) {
            return await this.authenticateDesktop(desktopPort, desktopRequestOptions);
        } else {
            return await this.authenticateWebAuthn(webauthnCredentialRequestOptions);
        }
    },

    async startConditionalRequest(publicKeyCredentialRequestOptions) {
        if (!window.PublicKeyCredential?.isConditionalMediationAvailable) {
            console.warn("Your browser does not support Conditional UI");
            return;
        }

        if (!await window.PublicKeyCredential.isConditionalMediationAvailable()) {
            console.warn("Conditional UI is not available");
            return;
        }

        if (this.abortController) {
            this.abortController.abort();
        }
        this.abortController = new AbortController();
        this.abortSignal = this.abortController.signal;

        try {
            const publicKeyCredential = this.prepareWebAuthnRequestOptions(publicKeyCredentialRequestOptions);
            const request = {
                signal: this.abortSignal,
                publicKey: publicKeyCredential,
                mediation: this.mediation
            };
            return await navigator.credentials.get(request)
                .then(assertion => this.parseWebAuthnAssertion(assertion))
                .catch(err => {
                    throw new Error(err);
                });
        } catch (error) {
            if (error.name !== "AbortError") {
                console.error(error.toString());
            }
            throw new Error(error);
        }
    },

    initAuthenticator(obj, submitFunction) {
        const attrs = obj.attributes;
        this.usernamelessAllowed = attrs['usernamelessAllowed'];
        this.origin = attrs['origin'];
        this.webauthnOptions = attrs['webauthnOptions'];
        this.desktopOptions = attrs['desktopOptions'];
        this.desktopPort = attrs['desktopPort'];
        this.desktopRpId = attrs['desktopRpId'];
        this.environmentId = attrs['environmentId'];
        this.usernamelessButtonLabel = attrs['usernamelessButtonLabel'];
        this.mediation = attrs['credUi'];
        this.abortController = new AbortController();
        this.abortSignal = this.abortController.signal;

        if (!this.usernamelessAllowed) {
            obj.button.remove();
            return;
        }

        obj.button.setAttribute('title', this.usernamelessButtonLabel);
        obj.button.text = this.usernamelessButtonLabel;

        if (this.webauthnOptions && this.mediation === "conditional") {
            if (obj.usernameField) obj.usernameField.setAttribute("autocomplete", "username webauthn");
            if (obj.passwordField) obj.passwordField.setAttribute("autocomplete", "current-password");
        }

        const handleAssertion = (assertion) => {
            if (assertion == null) {
                return;
            }
            this.assertionResponse = assertion;
            this.addHiddenInput(this.usernamelessAssertionFieldName, this.assertionResponse);
            submitFunction();
        }

        obj.button.onclick = () => {
            this.usernamelessAuthenticate(this.desktopPort, this.environmentId, this.desktopRpId, this.desktopOptions, this.webauthnOptions)
                .then(assertion => {
                    handleAssertion(assertion);
                })
                .catch(e => console.error(e));
        };

        const checkSSOResponse = () => {
            if (this.isSafari()) {
                const {
                    authToken: ssoExtensionAssertion,
                    error: ssoExtensionError
                } = this.getSSOExtensionQueryParams();

                // If user is not paired to desktop in Safari, fallback to passkeys logic
                if (ssoExtensionError && ssoExtensionError === "userNotFound") {
                    this.authenticateWebAuthn(this.webauthnOptions)
                        .then(assertion => {
                            handleAssertion(assertion);
                        })
                        .catch(e => console.error(e));
                }

                if (ssoExtensionAssertion) {
                    handleAssertion(ssoExtensionAssertion);
                }
            }
        };

        // Check immediately in case of page reload
        checkSSOResponse();
        // Listen for hash changes in case browser treats redirect as fragment navigation to avoid page reload
        window.addEventListener('hashchange', checkSSOResponse);

        if (this.webauthnOptions && (this.mediation === "optional" || this.mediation === "conditional")) {
            this.startConditionalRequest(this.webauthnOptions)
                .then(assertion => {
                    handleAssertion(assertion);
                })
                .catch(_ => {});
        }
    }
};

AuthenticatorSupport.registerAuthenticator(PasswordlessAuthenticator);
