import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

final class SqlGuarded {
  ResultSet find(Connection connection, String requestId) throws Exception {
    PreparedStatement statement = connection.prepareStatement("SELECT * FROM users WHERE id=?");
    statement.setInt(1, Integer.parseInt(requestId));
    return statement.executeQuery();
  }
}
