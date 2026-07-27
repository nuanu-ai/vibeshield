import java.sql.Connection;
import java.sql.ResultSet;

final class SqlInjection {
  ResultSet find(Connection connection, String requestId) throws Exception {
    return connection.createStatement().executeQuery("SELECT * FROM users WHERE id=" + requestId);
  }
}
