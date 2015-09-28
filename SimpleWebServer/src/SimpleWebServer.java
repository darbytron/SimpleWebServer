/***********************************************************************

   SimpleWebServer.java


   This toy web server is used to illustrate security vulnerabilities.
   This web server only supports extremely simple HTTP GET requests.

   This file is also available at http://www.learnsecurity.com/ntk
 
***********************************************************************/
                                
 
import java.io.*;                                         
import java.net.*;                                        
import java.util.*;                                       
 

public class SimpleWebServer {                            
	private static final int KILOBYTE = 1024;
    /* Run the HTTP server on this TCP port. */           
    private static final int PORT = 8080;
    private enum Status {
    	MALFORMED_HEADER,
    	MALFORMED_REQUEST,
    	FORBIDDEN,
    	MISSING_CONTENT_LENGTH,
    	TOO_LARGE,
    	NOT_IMPLEMENTED,
    	BAD_HTTP,
    	INTERNAL_ERROR
    }
    
 
    /* The socket used to process incoming connections
       from web clients */
    private static ServerSocket dServerSocket;            
   
    public SimpleWebServer () throws Exception {          
    	dServerSocket = new ServerSocket (PORT);          
    }                                                     
 
    public void run() throws Exception {  
    	System.out.println("Listening for requests");
		while (true) {                                   
	 	    /* wait for a connection from a client */
	 	    Socket s = dServerSocket.accept();           
	 
	 	    /* then process the client's request */
	 	    processRequest(s);                           
	 	}                                                
    }                                                    
 
    /* Reads the HTTP request from the client, and
       responds with the file the user requested or
       a HTTP error code. */
    public void processRequest(Socket s) throws Exception { 
    	
    	System.out.println("Request received. Processing...");
	 	/* used to read data from the client */ 
	 	BufferedReader br =                                 
	 	    new BufferedReader (
					new InputStreamReader (s.getInputStream())); 
	 
	 	/* used to write data to the client */
	 	OutputStreamWriter osw =                            
	 	    new OutputStreamWriter (s.getOutputStream());  
	     
	 	/* read the HTTP request from the client */
	 	
	 	String request = br.readLine();
	 	String contentLength  = new String();
	 	
	 	String line = br.readLine();
	 	/* Read the headers */
	 	while(line != null && !(line.equals(""))) {
	 		/* Getting the contentLength */
	 		/* Request must match <headername>: <value> */
		 	if(!line.matches("^.*:\\s.*$")){
		 		handleError(osw, Status.MALFORMED_HEADER);
		 		return;
		 	}
	 		if(line.startsWith("Content-Length:")){
	 			String split[] = line.split(" ");
	 			contentLength = split[split.length-1];
	 		}
	 		line = br.readLine();
	 	}
	 	
	 	System.out.println("REQUEST: " + request);
	 	
	 	/* The URL requested needs to be smaller than 1KB */
	 	if(request.getBytes("UTF-8").length > KILOBYTE) {
	 		handleError(osw, Status.TOO_LARGE);
	 		return;
	 	}
	 	
	 	String command = null;                             
	 	String pathname = null;
	 	String httpVersion = null;
	 	
	 	/* parse the HTTP request */
	 	StringTokenizer st = 
		    new StringTokenizer (request, " ");               
	 	if(st.countTokens() >= 3){
	 		command = st.nextToken();                       
		 	pathname = st.nextToken();
		 	httpVersion = st.nextToken();
	 	} else {
	 		handleError(osw, Status.MALFORMED_REQUEST);
	 		return;
	 	}
	 	
	 	System.out.println("HTTP-Version: " + httpVersion);
	 	if(httpVersion.equals("HTTP/1.1") || httpVersion.equals("HTTP/1.0")){
	 		
	 	} else {
	 		handleError(osw, Status.MALFORMED_REQUEST);
	 		return;
	 	}
	 	File tmpFile = new File("/", pathname);
	 	
	 	if(!(pathname.equals(tmpFile.getCanonicalPath()))){
	 		handleError(osw, Status.FORBIDDEN);
	 		return;
	 	}
	 	
	 
	 	System.out.println("Process parced. Analyzing command...");
		if (command.equals("GET")) {                    
		    /* if the request is a GET
		       try to respond with the file
		       the user is requesting */
		    serveFile (osw,pathname);                   
	 	} else if(command.equals("PUT")) {
	 		/*	if the request is a PUT 
	 		 	try to update the file 
	 		 	the user is specifying. 
	 		 */
	 		
	 		/* Request must include a content-length */
		 	if(contentLength == null) {
		 		handleError(osw, Status.MISSING_CONTENT_LENGTH);
		 		return;
		 	}
	 		updateFile(osw, pathname, br);
	 		
	 	} else {                                         
		    /* if the request is a NOT a GET or PUT
		       return an error saying this server
		       does not implement the requested command */
		    handleError(osw, Status.NOT_IMPLEMENTED);
		    return;
	 	}                                               
	 	
	 	/* close the connection to the client */
	 	osw.close();                                    
    }          
    
    public void validateHeaders(OutputStreamWriter osw, BufferedReader br){
    	
    }
 
    public void serveFile (OutputStreamWriter osw, String pathname) throws Exception {
	 	FileReader fr=null;                                 
	 	int c=-1;                                           
	 	StringBuffer sb = new StringBuffer();
	       
	 	/* remove the initial slash at the beginning
	 	   of the pathname in the request */
	 	if (pathname.charAt(0)=='/')                        
	 	    pathname=pathname.substring(1);                 
	 	
	 	/* if there was no filename specified by the
	 	   client, serve the "index.html" file */
	 	if (pathname.equals(""))                            
	 	    pathname="index.html";                          
	 
		 	/* try to open file specified by pathname */
		 	try {                                               
		 	    fr = new FileReader (pathname);                 
		 	    c = fr.read();                                  
		 	}                                                   
		 	catch (Exception e) {                               
		 	    /* if the file is not found,return the
		 	       appropriate HTTP response code  */
		 	    osw.write ("HTTP/1.0 404 Not Found\n\n");         
		 	    return;                                         
		 	}                                                   
 
		 	/* if the requested file can be successfully opened
		 	   and read, then return an OK response code and
		 	   send the contents of the file */
		 	osw.write ("HTTP/1.0 200 OK\n\n");                    
		 	while (c != -1) {       
			    sb.append((char)c);                            
		 	    c = fr.read();                                  
		 	}                                                   
		 	osw.write (sb.toString());                                  
    	}                                                       
 
    public void updateFile(OutputStreamWriter osw, String pathname, BufferedReader br) throws Exception {
    	System.out.println("Updating file...");
    	if(pathname.startsWith("/")){
    		pathname = pathname.substring(1);
    	}
    	
    	try {
    		File f = new File(pathname);
        	if(f != null && f.isFile()) {
        		osw.write("Request 200: File updated\n");
        	} else {
        		osw.write("Request 201: File created\n");
        	}
        	
    		BufferedWriter bw = new BufferedWriter(new FileWriter(f));
    		String line = null;
    		
    		while((line = br.readLine()) != null && !line.isEmpty()){
    			bw.write(line);
    			bw.newLine();
    		}
    		bw.close();
    		
    	} catch(Exception e) {
    		System.out.println("Something went wrong");
    	}	
		
    }
    
    
    public void handleError(OutputStreamWriter osw, Status st) throws Exception{
    	System.out.println("Handling error " + st);
    	String errorMessage;
    	int statusCode;
    	switch(st) {
	    	case MALFORMED_HEADER: {
	    		statusCode = 400;
	    		errorMessage = "Malformed request"; 
	    		break;
	    	}
	    	case MALFORMED_REQUEST : {
	    		statusCode = 400;
	    		errorMessage = "Malformed header"; 
	    	}
	    	case FORBIDDEN: {
	    		statusCode = 403;
	    		errorMessage = "Forbidden";
	    		break;
	    	}
	    	case MISSING_CONTENT_LENGTH: {
	    		statusCode = 411;
	    		errorMessage = "Missing content-length header";
	    		break;
	    	}
	    	case TOO_LARGE:
	    		statusCode = 414;
	    		errorMessage = "Too large of a request";
	    		break;
	    	case NOT_IMPLEMENTED: {
	    		statusCode = 501;
	    		errorMessage = "Not implemented";
	    		break;
	    	}
	    	case BAD_HTTP: {
	    		statusCode = 505;
	    		errorMessage = "Bad HTTP Version";
	    	}
	    	default: {
	    		statusCode = 500;
	    		errorMessage = "Internal error";
	    		break;
	    	}
    	}
    	String responseMessage = String.format("Return status %d: %s", statusCode, errorMessage);
    	osw.write(responseMessage + "\n\n");
    	osw.close();
    }

    
    /* This method is called when the program is run from
       the command line. */
    public static void main (String argv[]) throws Exception { 
    	System.out.println("Starting server...");
    	/* Create a SimpleWebServer object, and run it */
    	SimpleWebServer sws = new SimpleWebServer();           
    	sws.run();
    	System.out.println("Server running...");
 	
    }                                                          
}                                                              
