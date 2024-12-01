### 1. SQL Injection Vulnerability
Change sql Statement to PreparedStatement

```java
private boolean authenticated(String username, String password) throws SQLException {
    String query = "SELECT password FROM user WHERE username=?";
    try (PreparedStatement stmt = database.prepareStatement(query)) {
      stmt.setString(1, username);
      ResultSet results = stmt.executeQuery();
      if (results.next()) {
        String storedHash = results.getString("password");
        System.out.println(storedHash + " : " + password);
        return BCrypt.checkpw(password, storedHash);
      }
    }
    return false;
}
```

### 2. Plaintext Password Storage

1. alter password column type from char(8) to varchar(60), make it long enough to store encrypted text

2. write a golang script, convert the existing plaintext password to encrypted password (details in ./script/main.go)

3. using BCrypt in authenticated
```java
if (results.next()) {
    String storedHash = results.getString("password");
    return BCrypt.checkpw(password, storedHash);
}
```

### 3. Information Disclosure via Error Handling

using more meaningful error message, hide internal error from users
```java
log("Error processing request in doPost", error);
response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "An error occurred, please try again later.");
```

### 4. No Protection Against Brute Force Attacks

Add login attempt limitation and account lock time, to avoid Brute Force Attacks
```java
// Tracking login attempts
private Map<String, Integer> loginAttempts = new HashMap<>();
private Map<String, Long> lockTime = new HashMap<>();

private boolean canAttemptLogin(String username) {
  // Check if the account is locked
  if (lockTime.containsKey(username) && System.currentTimeMillis() - lockTime.get(username) < LOCK_TIME) {
    return false; // Account is locked, can't try login
  }
  return true;
}
private void incrementLoginAttempts(String username) {
  int attempts = loginAttempts.getOrDefault(username, 0);
  if (attempts >= MAX_LOGIN_ATTEMPTS) {
    // Lock the account if attempts exceeded
    lockTime.put(username, System.currentTimeMillis());
  } else {
    loginAttempts.put(username, attempts + 1);
  }
}
```

### 5. Session Management Issues

integrated csrf token validation
```java
// in doGet()
String csrfToken = generateCSRFToken();

request.getSession().setAttribute("csrfToken", csrfToken);

Map<String, Object> model = new HashMap<>();
model.put("csrfToken", csrfToken);


// in doPost()
String csrfTokenFromRequest = request.getParameter("csrfToken");

String csrfTokenFromSession = (String) request.getSession().getAttribute("csrfToken");

if (csrfTokenFromRequest == null || !csrfTokenFromRequest.equals(csrfTokenFromSession)) {
    response.sendError(HttpServletResponse.SC_FORBIDDEN, "CSRF Token is invalid or missing.");
    return;
}
```

```html
<!-- CSRF Token -->
<input type="hidden" name="csrfToken" value="${csrfToken}" />
```