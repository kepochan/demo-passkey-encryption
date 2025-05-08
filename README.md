# PassKey Encryption Demo

This project demonstrates how to use WebAuthn PassKeys for secure client-side encryption. It showcases the PRF (Pseudorandom Function) extension for generating encryption keys from PassKeys.

## Features

- WebAuthn PassKey registration and authentication
- PRF extension to generate cryptographic keys
- Client-side encryption/decryption with PassKey-derived keys

## Prerequisites

- Node.js 18+ and npm
- For PassKey support: 
  - Modern browser with WebAuthn support
  - Device with platform authenticator (TouchID, FaceID, Windows Hello, etc.)

## Development

### Installation

```bash
# Install dependencies
npm install
```

### Running the Development Server

```bash
# Start the dev server
npm run dev
```

The application will be available at [http://localhost:5173](http://localhost:5173).

## Docker Container

The project includes a Docker configuration for easy deployment.

```bash
# Build the Docker image
docker build -t passkey-encryption-demo .

# Run the container on port 8888
docker run -p 8888:80 passkey-encryption-demo
```

After running these commands, the application will be available at [http://localhost:8888](http://localhost:8888).

## Browser Compatibility

This demo relies on the WebAuthn PRF extension, which may not be supported by all browsers. For best results, use:

- Chrome/Edge 108+
- Safari 16.4+
- Firefox with appropriate flags enabled

## License

[MIT](LICENSE)
