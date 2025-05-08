import {
  browserSupportsWebAuthn,
  startRegistration,
  startAuthentication,
  browserSupportsWebAuthnAutofill
} from '@simplewebauthn/browser';
import type {
  PublicKeyCredentialCreationOptionsJSON
} from '@simplewebauthn/browser';

// Mock server values - in a real app these would come from a backend
// Convert Uint8Array to base64 string as required by the WebAuthn API
const mockChallenge = btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(32).fill(1))));
const mockUserId = btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(16).fill(2))));
const rpID = window.location.hostname || 'localhost';
const rpName = 'PassKey Encryption Demo';

export interface PassKeyStatus {
  registered: boolean;
  authenticated: boolean;
  message: string;
  supportsPRF?: boolean;
}

export class PassKeyService {
  private status: PassKeyStatus = {
    registered: false,
    authenticated: false,
    message: '',
    supportsPRF: undefined
  };
  
  // Store credential information from authentication if needed in the future
  private credentialInfo: { id?: string } = {};

  isSupported(): boolean {
    return browserSupportsWebAuthn();
  }

  async supportsAutofill(): Promise<boolean> {
    return browserSupportsWebAuthnAutofill();
  }

  getStatus(): PassKeyStatus {
    return this.status;
  }

  async register(): Promise<PassKeyStatus> {
    if (!this.isSupported()) {
      this.status.message = 'WebAuthn is not supported by this browser';
      return this.status;
    }

    try {
      // In a real app, you'd fetch these options from your server
      const registrationOptions: PublicKeyCredentialCreationOptionsJSON = {
        challenge: mockChallenge,
        rp: {
          name: rpName,
          id: rpID,
        },
        user: {
          id: mockUserId,
          name: 'user@example.com',
          displayName: 'Example User',
        },
        pubKeyCredParams: [
          {
            type: 'public-key',
            alg: -7, // ES256
          },
          {
            type: 'public-key',
            alg: -257, // RS256
          }
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          requireResidentKey: true,
          residentKey: 'required',
          userVerification: 'required',
        },
        attestation: 'none',
        extensions: {} // Remove prf extension from registration options as it's not properly typed
      };

      // This would normally be sent to your server for validation
      await startRegistration({
        optionsJSON: registrationOptions
      });
      
      // In a real application, you would verify this with your server
      this.status.registered = true;
      this.status.authenticated = true;
      this.status.message = 'PassKey registered successfully! Use "Check PRF Support" to verify encryption capabilities.';
      
      return this.status;
    } catch (error) {
      if ((error as Error).name === 'NotAllowedError') {
        // User already has registered this passkey
        this.status.registered = true;
        try {
          await this.authenticate();
          this.status.message = 'PassKey already exists and was validated. Use "Check PRF Support" to verify encryption capabilities.';
          return this.status;
        } catch (authError) {
          this.status.message = `PassKey already exists but authentication failed: ${(authError as Error).message}`;
          return this.status;
        }
      }
      
      this.status.message = `Failed to register PassKey: ${(error as Error).message}`;
      return this.status;
    }
  }

  async authenticate(): Promise<PassKeyStatus> {
    if (!this.isSupported()) {
      this.status.message = 'WebAuthn is not supported by this browser';
      return this.status;
    }

    try {
      // In a real app, you'd fetch these options from your server
      const authenticationOptions = {
        rpId: rpID,
        challenge: mockChallenge,
        allowCredentials: [],
        userVerification: 'required' as const,
      };

      // This would normally be sent to your server for validation
      const response = await startAuthentication({
        optionsJSON: authenticationOptions
      });
      
      // Store the credential ID for potential future use
      this.credentialInfo.id = response.id;

      // In a real application, you would verify this with your server
      this.status.authenticated = true;
      this.status.message = 'PassKey authentication successful!';
      
      return this.status;
    } catch (error) {
      this.status.authenticated = false;
      this.status.message = `Failed to authenticate: ${(error as Error).message}`;
      
      return this.status;
    }
  }

  /**
   * Gets a key using PRF extension. Throws an error if PRF is not available.
   * We do not provide any fallback for security reasons.
   */
  async getPRF(saltBytes: Uint8Array): Promise<ArrayBuffer> {
    if (!this.status.authenticated) {
      await this.authenticate();
    }

    try {
      // In a real app, you'd fetch these options from your server
      const prfOptions = {
        rpId: rpID,
        challenge: mockChallenge,
        allowCredentials: [],
        userVerification: 'required' as const,
      };

      // PRF extension is part of WebAuthn Level 2 but not in current typings
      // Need to use type assertion to bypass TypeScript checking
      const prfResponse = await startAuthentication({
        optionsJSON: {
          ...prfOptions,
          extensions: {
            // @ts-expect-error - PRF extension is valid but not in type definitions
            prf: {
              eval: {
                first: saltBytes.buffer // Pass the raw ArrayBuffer directly
              }
            }
          }
        }
      });
      
      // Store the credential ID for potential future use
      this.credentialInfo.id = prfResponse.id;
      
      // Access the PRF output
      const extensionResults = prfResponse.clientExtensionResults as unknown as {
        prf?: {
          results?: {
            first?: ArrayBuffer
          }
        }
      };
      
      if (extensionResults.prf?.results?.first) {
        this.status.supportsPRF = true;
        return extensionResults.prf.results.first;
      }
      
      // PRF extension not supported by this authenticator - we don't provide a fallback
      this.status.supportsPRF = false;
      throw new Error('Your authenticator does not support the PRF extension, which is required for encryption');
    } catch (error) {
      // Update the supportsPRF status if we detect PRF is not supported
      if ((error as Error).message.includes('PRF not available') || 
          (error as Error).message.includes('does not support the PRF extension')) {
        this.status.supportsPRF = false;
      }
      
      throw new Error(`Failed to get PRF: ${(error as Error).message}`);
    }
  }

  /**
   * Tests if the authenticator supports the PRF extension
   * This is a helper method to check PRF support after registration
   */
  private async testPRFSupport(saltBytes: Uint8Array): Promise<boolean> {
    try {
      // In a real app, you'd fetch these options from your server
      const prfOptions = {
        rpId: rpID,
        challenge: mockChallenge,
        allowCredentials: [],
        userVerification: 'required' as const,
      };

      // PRF extension is part of WebAuthn Level 2 but not in current typings
      const prfResponse = await startAuthentication({
        optionsJSON: {
          ...prfOptions,
          extensions: {
            // @ts-expect-error - PRF extension is valid but not in type definitions
            prf: {
              eval: {
                first: saltBytes.buffer
              }
            }
          }
        }
      });
      
      // Store the credential ID
      this.credentialInfo.id = prfResponse.id;
      
      // Check if PRF results are available
      const extensionResults = prfResponse.clientExtensionResults as unknown as {
        prf?: {
          results?: {
            first?: ArrayBuffer
          }
        }
      };
      
      // If PRF results exist, the authenticator supports PRF
      return !!extensionResults.prf?.results?.first;
    } catch {
      // Any error means PRF is not supported
      return false;
    }
  }

  /**
   * Checks if the authenticator supports the PRF extension
   * This is exposed as a separate user action to avoid double authentication
   */
  async checkPRFSupport(): Promise<PassKeyStatus> {
    try {
      // Create a small test salt
      const testSalt = new Uint8Array(8).fill(1);
      
      // Check if PRF is supported
      const isPRFSupported = await this.testPRFSupport(testSalt);
      
      // Update the status
      this.status.supportsPRF = isPRFSupported;
      if (isPRFSupported) {
        this.status.message = 'Your device supports the PRF extension required for encryption.';
      } else {
        this.status.message = 'Your device does not support the PRF extension required for encryption.';
      }
      
      return this.status;
    } catch (error) {
      this.status.supportsPRF = false;
      this.status.message = `Failed to check PRF support: ${(error as Error).message}`;
      return this.status;
    }
  }
}

export const passKeyService = new PassKeyService();