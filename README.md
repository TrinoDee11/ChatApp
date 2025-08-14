
# ChatLite (Node.js + Express + EJS + JWT)

A simple WhatsApp-like private messaging demo with:
- EJS pages (with `partials/header.ejs` and `partials/footer.ejs`)
- Public assets in `/public` (see `styles.css`)
- JWT auth stored in an HTTP-only cookie
- File-based JSON storage (users and messages) for simplicity
- Polling every 2 seconds to fetch new messages

> For learning/demo only; not production-hardened.

## Features
- Sign up and Login
- Logout
- See contacts (all other users)
- One-to-one chat with timestamps
- Messages persist in `data/messages.json`

## How to run
1. Install Node.js (v18+ recommended) from https://nodejs.org/
2. Open a terminal in this project folder.
3. Install dependencies:
   ```bash
   npm install
   ```
4. (Optional) set a JWT secret:
   ```bash
   set JWT_SECRET=super-strong-secret # Windows (cmd)
   export JWT_SECRET=super-strong-secret # macOS/Linux
   ```
5. Start the server:
   ```bash
   npm start
   ```
6. Visit http://localhost:3000 in your browser.

## Usage
- Register two accounts (e.g., "Cliff" and "John") using different emails.
- Open two different browsers or use a private/incognito window for the second user.
- Select a contact from the left list and start chatting.
- Timestamps are recorded in ISO and shown in your local time.

## Project structure
```
public/
  styles.css
views/
  pages/
    chat.ejs
    login.ejs
    register.ejs
    404.ejs
  partials/
    header.ejs
    footer.ejs
data/
  users.json
  messages.json
app.js
package.json
```

## Notes
- Data is saved to JSON files for simplicity. For real apps, use a database.
- JWT is stored in a cookie; the middleware attaches `currentUser` for templates.
- The chat UI polls every 2 seconds to show new messages; you could upgrade to WebSockets later.
