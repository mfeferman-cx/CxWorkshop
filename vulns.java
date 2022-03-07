import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.io.PrintWriter;

public class Vulns {

	private boolean loggedIn = false;
	private Result result;
	private HttpServletResponse response;
	private HttpServletRequest req;

	// SQLi vulnerability
	public static void input (DataSource pool) {
		try {

			String email = request.getParameter ("email");
			String password = request.getParameter ("password");

			//String sql = "select * from users where (email ='" + email + "' and password'" + password + "')";
			String sql = "select * from users where email = ? and password = ? ";

			Connection connection = pool.getConnection();
			//Statement statement = connection.createStatement();
			PreparedStatement ps = connection.prepareStatement(sql);
			//result = statement.executeQuery(sql);
			ps.setString(1, email);
			ps.setString(2, password);
			result = ps.executeQuery();

			if (result.next()) {
				loggedIn = true;
				doGet(result,req,response);
			} else {
				out.println("No results");
			}
		}
		catch()
		{
			out.println("Overly broad Exception");
		}
	}

	// XSS vulnerability	
	protected void doGet(Result res, HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
    
    		try {
			response.setContentType("text/html;charset=UTF-8");
			response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
      
  			PrintWriter out = response.getWriter();
  			String loc = request.getParameter("location");
			loc+=res.getString("GEO_LOC");
 			String escapedLocation = HtmlEscapers.htmlEscaper().escape(loc); 
  			out.println("<h1> Location: " + escapedLocation + "<h1>");
		}
		catch()	{
			out.println("Error caught by overly broad exception handler");
		}
	}
}