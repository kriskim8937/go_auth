# AuthFlow - OAuth 2.1 Authentication Service

## Overview
This project provides an OAuth 2.1 authentication and authorization system using Go and Redis as the backend for token storage. It follows the Authorization Code Flow, allowing secure authentication and access token management.

## Features
### 1. Authorization Code Flow
Supports client authorization requests via /auth/authorize
Redirects users to the specified callback URL with an authorization code

### 2. Token Exchange
Clients can exchange an authorization code for an access token via /auth/token
Implements OAuth-compliant token generation

### 3. Access Token Usage
Supports Bearer token authentication for API access
Provides a /auth/userinfo endpoint to retrieve user information using the access token

### 4. Security & Best Practices
Uses Redis for token storage, ensuring efficient and scalable session management
Follows standard OAuth 2.0 flows for secure authentication

## End-to-End Test
The E2E test verifies:
1. Authorization Request – Ensuring proper redirection with an authorization code
2. Token Exchange – Validating token generation upon code exchange
3. Token Usage – Ensuring valid access token retrieval of user info

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
│── README.md              # Documentation
```

## Installation
### Prerequisites
- Go 1.21+
- Docker & Docker Compose
- Reddis

### Setup
1. Clone the repository:
   ```sh
   git clone https://github.com/yourusername/authflow.git
   cd authflow
   ```
2. Set up environment variables in `.env`:
   ```sh
   cp .env.example .env
   ```
3. Build and run the service:
   ```sh
   go run main.go
   ```

## API Endpoints
| Method | Endpoint     | Description |
|--------|-------------|-------------|
| GET    | `/auth`     | Authorization endpoint |
| POST   | `/token`    | Token issuance |
| GET    | `/userinfo` | User information retrieval |

## Deployment
To deploy using Docker:
```sh
docker-compose up --build
```

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