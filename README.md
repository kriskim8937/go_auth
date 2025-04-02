# AuthFlow - OAuth 2.1 Authentication Service

## Overview
AuthFlow is a robust OAuth 2.1 authentication and authorization service built with Go and Redis for token storage. It implements the Authorization Code Flow to provide secure user authentication and effective access token management.

## Features
### 1. Authorization Code Flow
- Supports client authorization requests via the `/auth/authorize` endpoint.
- Redirects users to the specified callback URL with an authorization code.

### 2. Token Exchange
- Clients can exchange the authorization code for an access token via the `/auth/token` endpoint.
- Implements OAuth-compliant token generation.

### 3. Access Token Usage
- Supports Bearer token authentication for API access.
- Provides a `/auth/userinfo` endpoint to retrieve user information using the access token.

### 4. Security & Best Practices
- Utilizes Redis for efficient and scalable token storage.
- Follows standard OAuth 2.0 flows for secure authentication.

## End-to-End Test
The E2E tests verify the following:
1. **Authorization Request**: Ensures proper redirection with an authorization code.
2. **Token Exchange**: Validates token generation upon code exchange.
3. **Token Usage**: Confirms valid access token retrieval of user information.

## Project Structure
```
authflow/
├── internal/
│   ├── auth/
│   │   ├── handler.go     # API endpoints
│   │   ├── service.go     # Business logic
├── main.go                # Entry point
├── Dockerfile             # Containerization setup
├── docker-compose.yml     # Local development setup
│── .env                   # Environment variables
│── go.mod                 # Go module file
│── main.go                # Entry point
└── README.md              # Documentation
```

## Installation
### Prerequisites
- Go 1.21+
- Docker & Docker Compose
- Reddis

### Setup
1. Open VSCode and create a new empty folder.
2. Clone the repository:
   ```sh
   git clone https://github.com/kriskim8937/go_auth.git
   ```
3. Open the Command Palette by pressing Ctrl + Shift + P and select "Rebuild Container Without Cache" to set up the development environment.
4. The Redis service will start automatically. Once it is running, you can execute the end-to-end (E2E) tests.

## API Endpoints
| Method | Endpoint     | Description |
|--------|-------------|-------------|
| GET    | `/auth`     | Authorization endpoint |
| POST   | `/token`    | Token issuance |
| GET    | `/userinfo` | User information retrieval |

## Contributing
Contributions are welcome! Please open an issue or submit a pull request.

## License
MIT License

## TODO
This is the starting point for your OAuth 2.1 authentication service in Go using the Gin framework. Next steps:

Implement OAuth 2.1 flows (authorization code, client credentials).

Add PostgreSQL for token storage.

Secure the endpoints and integrate with third-party OAuth providers.

## 🚀 Project TODO List
| Task | Status     |
|--------|-------------|
| Project Setup    | ✅ Done     |
| Implemented Authorization Code Flow   | ✅ Done   |
| Implement Client Credentials Flow	| ✅ Done |
| Store & Manage Tokens Securely (Redis)	| ✅ Done  |
| Implement Token Revocation	| ⏳ Not Started |
| Implement Refresh Tokens	 | ⏳ Not Started |
| Secure API with Middleware (Token Validation)	| ⏳ Not Started |
| Deploy to Cloud (Google Cloud Run, Kubernetes)	|⏳ Not Started |