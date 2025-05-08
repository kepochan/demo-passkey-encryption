import { useState, useEffect } from 'react';
import './App.css';
import { passKeyService } from './services/PassKeyService';
import type { PassKeyStatus } from './services/PassKeyService';
import { encryptionService } from './services/EncryptionService';

function App() {
  // PassKey section state
  const [passKeyStatus, setPassKeyStatus] = useState<PassKeyStatus>({
    registered: false,
    authenticated: false,
    message: ''
  });
  const [isPassKeySupported, setIsPassKeySupported] = useState(false);
  const [checkingPRF, setCheckingPRF] = useState(false);
  
  // Encrypt section state
  const [encryptText, setEncryptText] = useState('');
  const [encryptedResult, setEncryptedResult] = useState('');
  const [encryptLoading, setEncryptLoading] = useState(false);
  
  // Decrypt section state
  const [decryptText, setDecryptText] = useState('');
  const [decryptedResult, setDecryptedResult] = useState('');
  const [decryptLoading, setDecryptLoading] = useState(false);
  
  // UI state
  const [sectionsEnabled, setSectionsEnabled] = useState({
    encrypt: false,
    decrypt: false
  });

  // Check PassKey support on component mount
  useEffect(() => {
    setIsPassKeySupported(passKeyService.isSupported());
  }, []);

  // Enable sections when PassKey is authenticated and PRF is supported
  useEffect(() => {
    if (passKeyStatus.authenticated) {
      setSectionsEnabled({
        encrypt: passKeyStatus.supportsPRF === true,
        decrypt: passKeyStatus.supportsPRF === true
      });
    }
  }, [passKeyStatus.authenticated, passKeyStatus.supportsPRF]);

  // Handle PassKey registration/authentication
  const handlePassKey = async () => {
    try {
      const status = await passKeyService.register();
      setPassKeyStatus(status);
    } catch (error) {
      setPassKeyStatus({
        ...passKeyStatus,
        message: `Error: ${(error as Error).message}`
      });
    }
  };

  // Handle PRF check
  const handleCheckPRF = async () => {
    setCheckingPRF(true);
    try {
      const status = await passKeyService.checkPRFSupport();
      setPassKeyStatus(status);
    } catch (error) {
      setPassKeyStatus({
        ...passKeyStatus,
        message: `Error: ${(error as Error).message}`
      });
    } finally {
      setCheckingPRF(false);
    }
  };

  // Handle encryption
  const handleEncrypt = async () => {
    if (!encryptText.trim()) return;
    
    setEncryptLoading(true);
    try {
      const encrypted = await encryptionService.encrypt(encryptText);
      setEncryptedResult(encrypted);
    } catch (error) {
      setEncryptedResult(`Error: ${(error as Error).message}`);
    } finally {
      setEncryptLoading(false);
    }
  };

  // Handle decryption
  const handleDecrypt = async () => {
    if (!decryptText.trim()) return;
    
    setDecryptLoading(true);
    try {
      const decrypted = await encryptionService.decrypt(decryptText);
      setDecryptedResult(decrypted);
    } catch (error) {
      setDecryptedResult(`Error: ${(error as Error).message}`);
    } finally {
      setDecryptLoading(false);
    }
  };

  // Handle copy to clipboard
  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  // Handle paste from clipboard
  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      setDecryptText(text);
    } catch {
      alert('Failed to read from clipboard');
    }
  };

  return (
    <div className="app-container">
      <h1>PassKey Encryption Demo</h1>
      
      {/* PassKey Section */}
      <section className="section passkey-section">
        <h2>PassKey Authentication</h2>
        {!isPassKeySupported ? (
          <div className="error-message">
            Your browser does not support PassKeys (WebAuthn).
          </div>
        ) : (
          <>
            <button 
              className="primary-button" 
              onClick={handlePassKey}
            >
              {passKeyStatus.registered ? 'Verify PassKey' : 'Create PassKey'}
            </button>
            
            <button 
              className="secondary-button" 
              onClick={handleCheckPRF}
              disabled={checkingPRF}
              title="Check PRF support"
            >
              {checkingPRF ? 'Checking PRF...' : 'Check PRF Support'}
            </button>
            
            {passKeyStatus.message && (
              <div className={`status-message ${passKeyStatus.authenticated ? 'success' : 'error'}`}>
                {passKeyStatus.message}
              </div>
            )}
            
            {passKeyStatus.authenticated && passKeyStatus.supportsPRF !== undefined && (
              <div className="feature-support">
                PRF Extension: <span className={passKeyStatus.supportsPRF ? 'success' : 'error'}>
                  {passKeyStatus.supportsPRF 
                    ? 'Supported ✓' 
                    : 'Not supported ✗ - Encryption unavailable'}
                </span>
                {!passKeyStatus.supportsPRF && (
                  <div className="error-note">
                    Your device does not support the PRF extension required for secure encryption.
                    Encryption and decryption features are disabled for security reasons.
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </section>
      
      {/* Encrypt Section */}
      <section className={`section encrypt-section ${sectionsEnabled.encrypt ? '' : 'disabled'}`}>
        <h2>Encrypt Text</h2>
        <textarea
          placeholder="Enter text to encrypt..."
          value={encryptText}
          onChange={(e) => setEncryptText(e.target.value)}
          disabled={!sectionsEnabled.encrypt}
        />
        
        {encryptText.trim() && sectionsEnabled.encrypt && (
          <button 
            className="primary-button" 
            onClick={handleEncrypt}
            disabled={encryptLoading}
          >
            {encryptLoading ? 'Encrypting...' : 'Encrypt'}
          </button>
        )}
        
        {encryptedResult && (
          <div className="result-container">
            <h3>Encrypted Text:</h3>
            <div className="result-box">
              <pre>{encryptedResult.startsWith('Error') ? encryptedResult : encryptedResult}</pre>
              {!encryptedResult.startsWith('Error') && (
                <button 
                  className="icon-button" 
                  onClick={() => handleCopy(encryptedResult)}
                  title="Copy to clipboard"
                >
                  Copy
                </button>
              )}
            </div>
          </div>
        )}
      </section>
      
      {/* Decrypt Section */}
      <section className={`section decrypt-section ${sectionsEnabled.decrypt ? '' : 'disabled'}`}>
        <h2>Decrypt Text</h2>
        <div className="input-with-button">
          <textarea
            placeholder="Paste encrypted text here..."
            value={decryptText}
            onChange={(e) => setDecryptText(e.target.value)}
            disabled={!sectionsEnabled.decrypt}
          />
          <button 
            className="icon-button" 
            onClick={handlePaste}
            disabled={!sectionsEnabled.decrypt}
            title="Paste from clipboard"
          >
            Paste
          </button>
        </div>
        
        {decryptText.trim() && sectionsEnabled.decrypt && (
          <button 
            className="primary-button" 
            onClick={handleDecrypt}
            disabled={decryptLoading}
          >
            {decryptLoading ? 'Decrypting...' : 'Decrypt'}
          </button>
        )}
        
        {decryptedResult && (
          <div className="result-container">
            <h3>Decrypted Text:</h3>
            <div className="result-box">
              <pre>{decryptedResult}</pre>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}

export default App;
