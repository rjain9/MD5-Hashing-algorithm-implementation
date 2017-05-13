import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.sql.*;

@WebServlet(urlPatterns = {"/FormLogin"})
public class FormLogin extends HttpServlet {
    
    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        PrintWriter out = response.getWriter();
        MD5Algo hash = new MD5Algo();
        try {
            Connection con;
            Statement stmt;
            ResultSet rs;
            Class.forName("sun.jdbc.odbc.JdbcOdbcDriver");
            con = DriverManager.getConnection("jdbc:odbc:MD5Demo");
            stmt = con.createStatement();
            String email = request.getParameter("email");
            String password1 = request.getParameter("password");
            String password = hash.toHexString(hash.computeMD5(password1.getBytes()));
            String s = "select email, password from member";
            rs = stmt.executeQuery(s);
            int flag=0;
            
            while(rs.next()){
                
                if(rs.getString(1).equals(email) && rs.getString(2).equals(password)){    
                    flag=1;                    
                }
            }
            if(flag==1){
                out.println("<h4>Login Successfull</h4><br><hr>");
                out.println("<h2>Report</h2>");
                out.println("<p>Input Password (plaintext) in String Format : "+password1+"</p>");
                out.println("<p>Input Password (md5 hash) in Hexadecimal Format : "+password+"</p>");
                out.println("<p>Match successfully found</p>");
            }
            else{
                out.println("<h4>Login Failed</h4><br><hr>");
                out.println("<h2>Report</h2>");
                out.println("<p>Input Password (plaintext) in String Format : "+password1+"</p>");
                out.println("<p>Input Password (md5 hash) in Hexadecimal Format : "+password+"</p>");
                out.println("<p>Match not found</p>");
            }
        }
        catch(Exception e){
            //out.println(e);
        }
        finally {
            out.println("<a href='index.html'>Back To Home</a>'");
            out.close();
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }
	
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

}


