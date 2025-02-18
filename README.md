# Multi-Device Authentication System

This project implements a multi-device authentication system using **FastAPI**, **Redis**, and **JWT**. The system allows users to sign in from multiple devices while maintaining session security.

## Project Overview

The repository provides a robust authentication mechanism that:
- Supports multiple device logins per user.
- Uses **FastAPI** as the backend framework.
- Implements **JWT (JSON Web Token)** for authentication.
- Leverages **Redis** for session storage and token management.
- Provides secure and efficient authentication workflows.

## Features Implemented

- **User Authentication**: Users can sign up, log in, and manage sessions.
- **Multi-Device Support**: Allows multiple sessions per user across devices.
- **JWT-Based Authentication**: Secure token-based authentication.
- **Redis Session Management**: Tokens are stored and managed efficiently in Redis.
- **FastAPI Endpoints**: Provides endpoints for authentication workflows.

## Prerequisites

Ensure you have the following installed:
- [Python 3.9+](https://www.python.org/)
- [Redis](https://redis.io/)
- [FastAPI](https://fastapi.tiangolo.com/)

## Installation

1. Clone the repository:
   ```sh
   git clone https://github.com/emperorsixpacks/multi_device_sign_in_with_redis.git
   cd multi_device_sign_in_with_redis
   ```
2. Install dependencies:
   ```sh
   cd server && poetry shell
   ```
4. Start Redis server (if not already running):
   ```sh
   redis-server
   ```
5. Run the FastAPI server:
   ```sh
   uvicorn main:app --reload
   ```

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

## License

This project is licensed under the MIT License.

## References

For more details, check out the full article: [HackerNoon Article](https://hackernoon.com/how-to-implement-multi-device-authentication-system-with-fastapi-redis-and-jwt)

