import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.sql.*;

@WebServlet(urlPatterns = {"/FormRegister"})
public class FormRegister extends HttpServlet {

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
            
            String password1=request.getParameter("password");
            String email=request.getParameter("email");
            String password = hash.toHexString(hash.computeMD5(password1.getBytes()));
            String checkquery = "select email from member";
            String insertquery = "insert into member values('"+email+"','"+password+"')";
            
            rs = stmt.executeQuery(checkquery);
            int flag=0;
            while(rs.next()){
                if(rs.getString(1).equals((email))){
                    //already exists
                    flag=1;
                    break;
                }
            }
            if(flag==1) {
                out.println("<h4>Entry Already Exists</h4>");
            }
            else{
                out.println("<h4>Registration Successful</h4><br><hr>");
                out.println("<h2>Report</h2>");
                out.println("<p>Input Password (plaintext) in String Format : "+password1+"</p>");
                out.println("<p>Input Password (md5 hash) in Hexadecimal Format : "+password+"</p>");
                out.println("<p>Plaintext Length : "+password1.length()+"</p>");
                out.println("<p>Hash Length (bits) : "+(password.length()*4)+"</p>");
                stmt.executeQuery(insertquery);
                
            }
        }
        catch(Exception e){
            //out.println(e.toString());
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

class MD5Algo
{
  private final int INIT_A = 0x67452301;
  private final int INIT_B = (int)0xEFCDAB89L;
  private final int INIT_C = (int)0x98BADCFEL;
  private final int INIT_D = 0x10325476;
 
  private final int[] SHIFT_AMTS = {
    7, 12, 17, 22,
    5,  9, 14, 20,
    4, 11, 16, 23,
    6, 10, 15, 21
  };
 
  private final int[] TABLE_T = new int[64];
  {
    for (int i = 0; i < 64; i++)
      TABLE_T[i] = (int)(long)((1L << 32) * Math.abs(Math.sin(i + 1)));
  }
 
  public byte[] computeMD5(byte[] message)
  {
    int messageLenBytes = message.length;
    int numBlocks = ((messageLenBytes + 8) >>> 6) + 1;
    int totalLen = numBlocks << 6;
    byte[] paddingBytes = new byte[totalLen - messageLenBytes];
    paddingBytes[0] = (byte)0x80;
 
    long messageLenBits = (long)messageLenBytes << 3;
    for (int i = 0; i < 8; i++)
    {
      paddingBytes[paddingBytes.length - 8 + i] = (byte)messageLenBits;
      messageLenBits >>>= 8;
    }
 
    int a = INIT_A;
    int b = INIT_B;
    int c = INIT_C;
    int d = INIT_D;
    int[] buffer = new int[16];
    for (int i = 0; i < numBlocks; i ++)
    {
      int index = i << 6;
      for (int j = 0; j < 64; j++, index++)
        buffer[j >>> 2] = ((int)((index < messageLenBytes) ? message[index] : paddingBytes[index - messageLenBytes]) << 24) | (buffer[j >>> 2] >>> 8);
      int originalA = a;
      int originalB = b;
      int originalC = c;
      int originalD = d;
      for (int j = 0; j < 64; j++)
      {
        int div16 = j >>> 4;
        int f = 0;
        int bufferIndex = j;
        switch (div16)
        {
          case 0:
            f = (b & c) | (~b & d);
            break;
 
          case 1:
            f = (b & d) | (c & ~d);
            bufferIndex = (bufferIndex * 5 + 1) & 0x0F;
            break;
 
          case 2:
            f = b ^ c ^ d;
            bufferIndex = (bufferIndex * 3 + 5) & 0x0F;
            break;
 
          case 3:
            f = c ^ (b | ~d);
            bufferIndex = (bufferIndex * 7) & 0x0F;
            break;
        }
        int temp = b + Integer.rotateLeft(a + f + buffer[bufferIndex] + TABLE_T[j], SHIFT_AMTS[(div16 << 2) | (j & 3)]);
        a = d;
        d = c;
        c = b;
        b = temp;
      }
 
      a += originalA;
      b += originalB;
      c += originalC;
      d += originalD;
    }
 
    byte[] md5 = new byte[16];
    int count = 0;
    for (int i = 0; i < 4; i++)
    {
      int n = (i == 0) ? a : ((i == 1) ? b : ((i == 2) ? c : d));
      for (int j = 0; j < 4; j++)
      {
        md5[count++] = (byte)n;
        n >>>= 8;
      }
    }
    return md5;
  }
 
  public String toHexString(byte[] b)
  {
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < b.length; i++)
    {
      sb.append(String.format("%02X", b[i] & 0xFF));
    }
    return sb.toString();
  }
}
