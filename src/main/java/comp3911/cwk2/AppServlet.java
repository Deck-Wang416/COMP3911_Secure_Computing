package comp3911.cwk2;

import java.io.File;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.mindrot.jbcrypt.BCrypt;

import freemarker.template.Configuration;
import freemarker.template.Template;
import freemarker.template.TemplateException;
import freemarker.template.TemplateExceptionHandler;

@SuppressWarnings("serial")
public class AppServlet extends HttpServlet {

  private static final String CONNECTION_URL = "jdbc:sqlite:db.sqlite3";
  // private static final String AUTH_QUERY = "select * from user where
  // username='%s' and password='%s'";
  // private static final String SEARCH_QUERY = "select * from patient where
  // surname='%s' collate nocase";

  private final Configuration fm = new Configuration(Configuration.VERSION_2_3_28);
  private Connection database;

  @Override
  public void init() throws ServletException {
    configureTemplateEngine();
    connectToDatabase();
  }

  private void configureTemplateEngine() throws ServletException {
    try {
      fm.setDirectoryForTemplateLoading(new File("./templates"));
      fm.setDefaultEncoding("UTF-8");
      fm.setTemplateExceptionHandler(TemplateExceptionHandler.HTML_DEBUG_HANDLER);
      fm.setLogTemplateExceptions(false);
      fm.setWrapUncheckedExceptions(true);
    } catch (IOException error) {
      throw new ServletException(error.getMessage());
    }
  }

  private void connectToDatabase() throws ServletException {
    try {
      database = DriverManager.getConnection(CONNECTION_URL);
    } catch (SQLException error) {
      throw new ServletException(error.getMessage());
    }
  }

  private static final int MAX_LOGIN_ATTEMPTS = 5;
  private static final long LOCK_TIME = 10 * 60 * 1000; // Lock for 10 minutes

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

  @Override
  protected void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    try {
      String csrfToken = generateCSRFToken();

      // 将 CSRF Token 存储到 session 中
      request.getSession().setAttribute("csrfToken", csrfToken);

      // 将 CSRF Token 传递给模板
      Map<String, Object> model = new HashMap<>();
      model.put("csrfToken", csrfToken);

      Template template = fm.getTemplate("login.html");
      template.process(model, response.getWriter());
      response.setContentType("text/html");
      response.setStatus(HttpServletResponse.SC_OK);
    } catch (TemplateException error) {
      log("Error processing template in doGet", error);
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "An error occurred, please try again later.");
    }
  }

  @Override
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    String csrfTokenFromRequest = request.getParameter("csrfToken");

    String csrfTokenFromSession = (String) request.getSession().getAttribute("csrfToken");

    if (csrfTokenFromRequest == null || !csrfTokenFromRequest.equals(csrfTokenFromSession)) {
      response.sendError(HttpServletResponse.SC_FORBIDDEN, "CSRF Token is invalid or missing.");
      return;
    }

    // Get form parameters
    String username = request.getParameter("username");
    String password = request.getParameter("password");
    String surname = request.getParameter("surname");

    if (!canAttemptLogin(username)) {
      response.sendError(HttpServletResponse.SC_FORBIDDEN, "Account is locked. Try again later.");
      return;
    }

    try {
      if (authenticated(username, password)) {
        loginAttempts.put(username, 0);

        // Get search results and merge with template
        Map<String, Object> model = new HashMap<>();
        model.put("records", searchResults(surname));
        Template template = fm.getTemplate("details.html");
        template.process(model, response.getWriter());
      } else {
        incrementLoginAttempts(username);

        Template template = fm.getTemplate("invalid.html");
        template.process(null, response.getWriter());
      }
      response.setContentType("text/html");
      response.setStatus(HttpServletResponse.SC_OK);
    } catch (Exception error) {
      log("Error processing request in doPost", error);
      response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "An error occurred, please try again later.");
    }
  }

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

  private List<Record> searchResults(String surname) throws SQLException {
    List<Record> records = new ArrayList<>();
    String query = "SELECT * FROM patient WHERE surname=? COLLATE NOCASE";
    try (PreparedStatement stmt = database.prepareStatement(query)) {
      stmt.setString(1, surname);
      ResultSet results = stmt.executeQuery();
      while (results.next()) {
        Record rec = new Record();
        rec.setSurname(results.getString(2));
        rec.setForename(results.getString(3));
        rec.setAddress(results.getString(4));
        rec.setDateOfBirth(results.getString(5));
        rec.setDoctorId(results.getString(6));
        rec.setDiagnosis(results.getString(7));
        records.add(rec);
      }
    }
    return records;
  }

  private String generateCSRFToken() {
    return UUID.randomUUID().toString(); // 生成一个随机的 CSRF token
  }
}
