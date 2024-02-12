# Kinde Golang Starter Kit

This is the official Kinde SDK for Golang.

## Getting Started

To start using the Kinde SDK, follow these steps:

1. Rename `.env.sample` to `.env`.
2. Open `.env` and replace the placeholder values with your actual Kinde credentials obtained from Kinde admin.

```
KINDE_CLIENT_ID=<YOUR_CLIENT_ID>
KINDE_CLIENT_SECRET=<YOUR_CLIENT_SECRET>
KINDE_ISSUER_URL=https://<YOUR_SUBDOMAIN>.kinde.com
KINDE_SITE_URL=http://localhost:3000
KINDE_POST_LOGOUT_REDIRECT_URL=http://localhost:3000
KINDE_POST_LOGIN_REDIRECT_URL=http://localhost:3000/dashboard
```

## Running the application

To run the application locally on http://localhost:3000, use the following command:

```
npm start
```

