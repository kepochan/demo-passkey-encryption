import CryptoJS from 'crypto-js';
import { passKeyService } from './PassKeyService';

// Salt for PBKDF2 key derivation
const SALT = 'passkey-encryption-demo-salt';
// Number of iterations for PBKDF2
const ITERATIONS = 10000;
// Key size in bytes - 256 bits for AES-256
const KEY_SIZE = 32;

export class EncryptionService {
  /**
   * Derives an AES key from a PassKey PRF output
   * @param prfOutput - The random output from the PassKey PRF
   * @returns The derived encryption key
   */
  private deriveKey(prfOutput: ArrayBuffer): CryptoJS.lib.WordArray {
    // Convert ArrayBuffer to WordArray
    const prfWordArray = CryptoJS.lib.WordArray.create(
      new Uint8Array(prfOutput),
      prfOutput.byteLength
    );
    
    // Derive a key using PBKDF2
    return CryptoJS.PBKDF2(
      prfWordArray.toString(CryptoJS.enc.Base64),
      SALT,
      {
        keySize: KEY_SIZE / 4, // keySize is in words (4 bytes each)
        iterations: ITERATIONS,
      }
    );
  }

  /**
   * Encrypts text using AES-GCM with a key derived from the PassKey PRF
   * @param plaintext - The text to encrypt
   * @returns A promise resolving to the encrypted text
   */
  async encrypt(plaintext: string): Promise<string> {
    try {
      // Generate a random salt for the PRF (could be specific to each message)
      const salt = CryptoJS.lib.WordArray.random(16);
      const saltBytes = new Uint8Array(salt.words.length * 4);
      
      // Convert WordArray to Uint8Array
      const words = salt.words;
      for (let i = 0; i < words.length; i++) {
        const word = words[i];
        const offset = i * 4;
        saltBytes[offset] = (word >> 24) & 0xff;
        saltBytes[offset + 1] = (word >> 16) & 0xff;
        saltBytes[offset + 2] = (word >> 8) & 0xff;
        saltBytes[offset + 3] = word & 0xff;
      }
      
      // Get PRF output for this salt
      const prfOutput = await passKeyService.getPRF(saltBytes);
      
      // Derive encryption key from PRF output
      const key = this.deriveKey(prfOutput);
      
      // Generate a random IV for AES
      const iv = CryptoJS.lib.WordArray.random(16);
      
      // Perform AES encryption
      const encrypted = CryptoJS.AES.encrypt(plaintext, key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      });
      
      // Combine salt, IV, and ciphertext for storage/transmission
      const result = {
        salt: salt.toString(CryptoJS.enc.Base64),
        iv: iv.toString(CryptoJS.enc.Base64),
        ciphertext: encrypted.toString()
      };
      
      // Return as JSON string
      return JSON.stringify(result);
    } catch (error) {
      throw new Error(`Encryption failed: ${(error as Error).message}`);
    }
  }

  /**
   * Decrypts text using AES-GCM with a key derived from the PassKey PRF
   * @param encryptedData - The encrypted data (JSON string)
   * @returns A promise resolving to the decrypted text
   */
  async decrypt(encryptedData: string): Promise<string> {
    try {
      // Parse the encrypted data
      const { salt, iv, ciphertext } = JSON.parse(encryptedData);
      
      // Convert Base64 salt to Uint8Array for PRF
      const saltWordArray = CryptoJS.enc.Base64.parse(salt);
      const saltBytes = new Uint8Array(saltWordArray.words.length * 4);
      
      // Convert WordArray to Uint8Array
      const words = saltWordArray.words;
      for (let i = 0; i < words.length; i++) {
        const word = words[i];
        const offset = i * 4;
        saltBytes[offset] = (word >> 24) & 0xff;
        saltBytes[offset + 1] = (word >> 16) & 0xff;
        saltBytes[offset + 2] = (word >> 8) & 0xff;
        saltBytes[offset + 3] = word & 0xff;
      }
      
      // Get PRF output using the same salt
      const prfOutput = await passKeyService.getPRF(saltBytes);
      
      // Derive the same key
      const key = this.deriveKey(prfOutput);
      
      // Parse IV
      const ivWordArray = CryptoJS.enc.Base64.parse(iv);
      
      // Decrypt
      const decrypted = CryptoJS.AES.decrypt(ciphertext, key, {
        iv: ivWordArray,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
      });
      
      // Convert to UTF-8 string
      return decrypted.toString(CryptoJS.enc.Utf8);
    } catch (error) {
      throw new Error(`Decryption failed: ${(error as Error).message}`);
    }
  }
}

export const encryptionService = new EncryptionService();