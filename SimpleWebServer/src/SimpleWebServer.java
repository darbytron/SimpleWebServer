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
    /* Enum to used to map the status of the request to the appropriate error */
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
 	private String command = null;                             
 	private String pathname = null;
 	private String httpVersion = null;
   
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
    	
	 	/* used to read data from the client */ 
	 	BufferedReader br =                                 
	 	    new BufferedReader (
					new InputStreamReader (s.getInputStream())); 
	 
	 	/* used to write data to the client */
	 	OutputStreamWriter osw =                            
	 	    new OutputStreamWriter (s.getOutputStream());  
	 	
	 	/*Send in the reader and output stream writer to validate the request. If we get an error, we handle the error in the validation method and will return*/
	 	if(!isValidRequest(osw, br)){
	 		System.out.println("Request not valid");
	 		return;
	 	}
	 	
	 	System.out.printf("Process parced. Analyzing command: %s \npathname: %s\n", command, pathname);
		if (command.equals("GET")) {                    
		    /* if the request is a GET
		       try to respond with the file
		       the user is requesting */
		    serveFile (osw,pathname);                   
	 	} else if(command.equals("PUT")) {
	 		/*	if the request is a PUT 
	 		 	update or create the file 
	 		 	the user is specifying. 
	 		 */
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
    
    /**
     *  Validates the request. Validates :
     *  	The headers are properly formatted
     *  	There is a content-length header for PUT requests
     *  	The request isn't too large
     *  	The HTTP Version is 1.0 or 1.1
     *  	The path is in or under our working directory
     * @param osw
     * @param br
     * @return boolean stating if the request was valid. 
     * @throws Exception
     */
    
    private boolean isValidRequest(OutputStreamWriter osw, BufferedReader br) throws Exception{
    	
    	
    	String request = br.readLine();
	 	String contentLength  = new String();
	 	String line = br.readLine();
	 	
	 	System.out.println("Reading headers");
	 	/* Read the headers */
	 	while(line != null && !(line.equals(""))) {
	 		
	 		/* Request must match <headername>: <value> */
		 	if(!line.matches("^.*:\\s.*$")){
		 		System.out.println("Invalid header");
		 		handleError(osw, Status.MALFORMED_HEADER);
		 		return false;
		 	}
	 		if(line.startsWith("Content-Length:")){
	 			/* Will need to check the content length on a PUT request. */
	 			String split[] = line.split(" ");
	 			contentLength = split[split.length-1];
	 		}
	 		line = br.readLine();
	 	}
	 	
	 	System.out.println("Getting bytes");
	 	/* The URL requested needs to be smaller than 1KB */
	 	if(request.getBytes("UTF-8").length > KILOBYTE) {
	 		System.out.println("Too large");
	 		handleError(osw, Status.TOO_LARGE);
	 		return false;
	 	}
	
	 	System.out.println("Parsing request");
	 	/* parse the HTTP request */
	 	StringTokenizer st = 
		    new StringTokenizer (request, " ");               
	 	if(st.countTokens() >= 3){
	 		command = st.nextToken();                       
		 	pathname = st.nextToken();
		 	httpVersion = st.nextToken();
	 	} else {
	 		System.out.println("Bad request");
	 		handleError(osw, Status.MALFORMED_REQUEST);
	 		return false;
	 	}
	 	
	 	System.out.println("Checking http");
	 	/* HTTP Version needs to be either 1.0 or 1.1 */
	 	if(!(httpVersion.equals("HTTP/1.1") || httpVersion.equals("HTTP/1.0"))){
	 		System.out.println("bad http");
	 		handleError(osw, Status.BAD_HTTP);
	 		return false;
	 	}
	 	
	 	System.out.println("Checking path");
	 	/*Path has to be in or under the current directory */
	 	File tmpFile = new File("/", pathname);
	 	if(!(pathname.equals(tmpFile.getCanonicalPath()))){
	 		handleError(osw, Status.FORBIDDEN);
	 		return false;
	 	}

 		/* Request must include a content-length */
	 	if(contentLength == null && command.equals("PUT")) {
	 		handleError(osw, Status.MISSING_CONTENT_LENGTH);
	 		return false;
	 	}
    	
    	return true;
    }
    
    /**
     * updateFile performs the PUT request, updating or creating the file requested
     */         
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
    		handleError(osw, Status.INTERNAL_ERROR);
    	}	
		
    }
    
    /**
     * handleError writes the appropriate error to the output stream writer and close the writer to end the request
     * @param osw - Passed in so we can write the appropriate response and close
     * @param st - Status enum type used to identify which error we should present to the requester
     * @throws Exception
     */
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
	    		break;
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
	    		break;
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
