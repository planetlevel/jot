# Java Observability Toolkit (JOT)

The Java Observability Toolkit (JOT) is a platform for making any Java application observable
without writing any code or even recompiling. JOT consists of...

- a library that you can add to your applications
- a set of JOTs that you can enable to make different aspects of your application observable.

You can create JOTs quickly and easily without any coding. JOTs can make
just about anything in a running Java application observable. Here are
a few examples of what you might use it for... but the only limit is your
creativity.

- You're stuck troubleshooting a production issue and you don't have enough
logs or the ability to debug.  With a simple JOT rule you can get the data
you need quickly and easily.

- You want to monitor something that's only accessible deep inside an app
and you don't have a way to expose it to your tools.

- You want to prevent abuse of powerful methods by attackers, but they're in libraries
that you don't control.

JOTs goal is to provide maximum instrumentation power without compromising simplicity.

Let us know the cool things you do with JOT! And consider contributing them back
to the project so that others can share in your awesomeness. The easiest way to contribute
is to create a pull request. If you're sharing a JOT, add it to the projects' "contrib"
directory... and please include a comment detailing what it's intended to be used for.


## A Simple JOT

Define your sensors and reports in yaml and save it in a .jot file. Sensors define what data
to capture and "reports" tell JOT how to track the data over time. 

    sensors:
    - name: "get-ciphers"
      description: "Identifies encryption ciphers"
      methods:
      - "javax.crypto.Cipher.getInstance"
      captures:
      - "#P0"
    
    reports:
    - name: "Encryption Usage"
      type: "list"
      cols: "get-ciphers"  

Launch Java with "-javaagent:jot.jar=ciphers.jot".
You might find using the JAVA_TOOL_OPTIONS environment variable useful.
Like "export JAVA_TOOL_OPTIONS="-javaagent:jot.jar=ciphers.jot"
Then you just use your application normally and let JOT gather data for you.
JOT will make a nice table capturing exactly where encryption is used and
what algorithm is specified.

    Encryption Algorithms                                        get-ciphers            
    ------------------------------------------------------------ ---------------------- 
    com.acme.ticketbook.Ticket.encrypt(Ticket.java:125)          DES                    
    org.apache.jsp.accessA_jsp._jspService(accessA_jsp.java:212) AES                    
    org.apache.jsp.accessA_jsp._jspService(accessA_jsp.java:213) PBEWithMD5AndTripleDES 
    org.apache.jsp.accessB_jsp._jspService(accessB_jsp.java:212) DES                    
    org.apache.jsp.accessC_jsp._jspService(accessC_jsp.java:212) DES/CBC/PKCS5Padding   

The captures are actually Spring Expression Language (SpEL) expressions, so once you
capture an object, you can call methods, compare stuff, and do operations. This helps
you observe exactly what you want. See below for all the details of writing your own sensors.


## Creating Your Own JOT Sensors

Sensors are how you define the data you want to gather. You can also use
sensors to perform limited actions within an application.
    
    # The name of this sensor, which can be referenced by reports
    - name: "get-ciphers"
    
	  # Use this to describe what this sensor does. Try to provide enough
	  # detail so that anyone would understand what it's about.
	  description: "What does sensor do?"
	
	  # A list of methods to gather data from. To avoid potential performance issues,
	  # avoid putting sensors in methods that are extremely frequently used,
	  # like StringBuffer.append() or File.<init>.
	  methods: 
	  - "a.b.c.Class.method"
	  - "d.e.f.Class.method"
	  
	  # Scopes allow you to limit when a sensor will fire.
	  # A sensor will fire if it is invoked while "inside" one of the scopes. That is,
	  # when any of these methods is on the stack.
	  # You can define negative scopes using !scope, so that this sensor will only fire outside the scope
	  # For static methods you need to prefix the method with "static"
	  scopes: 
	  - "a.b.c.Class.method"                 # matches only if inside method
	  - "!a.b.c.Class.method"                # matches only if NOT inside method
	  - "static a.b.c.Class.method"          # matches if inside static method
	  
	  # Excludes allow you to prevent data from being gathered from any
	  # classes that starts with any of these patterns or are "isAssignableFrom" these classes
	  # FIXME: currently you must put .all after each classname
	  excludes:  
	  - "javax.el.MapELResolver.all"         
	  - "org.foo.package.all"
	  
	  # Captures are the workhorse of JOT and are written in Spring Expression Language (SpEL)
	  # You may reference data from the method currently running.
	  # Options are OBJ, P1..P10, ARGS, RET, STACK. These objects are whatever type they happen
	  # to be, and you can invoke any existing methods on those objects. Note that STACK is a StackFrame[]
	  # See https://blog.abelotech.com/posts/useful-things-spring-expression-language-spel/
	  captures: 
	  - "#RET?.toUpperCase()"                # call toUpperCase if #RET is not null (note ?. operator)
	  - "\"\"+#P0+\":\"+#RET"                # for methods that take a name and return a value
	  - "#OBJ.getCanonicalPath() + \" \" + #OBJ.exists() ? [EXISTS] : [DOES NOT EXIST]"   # use ternary operator
	  - "\"\"+#P0+\":\"+(#RET ? \"Y\" : \"N\")"          # for methods that return boolean
	  
	  # Matchers allow you to filter the data that was captured with a set of regular expressions.
	  # If there are no matchers then all captures will report data.
	  # Positive matchers only fire if the data matches the pattern. You'll get a result if any positive matchers match.
	  # Negative matchers (starting with !) only fire if the data does not match the pattern. You'll get a result if no negative matchers match.
	  # If you mix positive and negative, you'll get a result if any positive captures match and no negative matchers match.
	  matchers:
	  - "^\\w*$"                             # matches anything with word characters start to finish
	  - "!^\\[foo"                           # matches anything that doesn't start with foo
	  - "!null"                              # hide empty results from output
	  
	  # Exceptions are a way to change the behavior of an application.
	  # If the sensor fires (capture occurs and matchers fire) then JOT will
	  # throw a SensorException.
	  # The message should be appropriate for end user, JOT will log all the relevant details.
	  # Note that generally you don't want to use #RET in your capture if you're throwing an exception,
	  # because it will throw at the end of the method, which is probably too late.
	  exception: "Message"
	
	  # Debug mode will generate extra logging for this rule only
	  debug: "false"
	
  

## Creating Your Own JOT Reports

Reports let you define how JOT will collect data over time and
how it will format it for you. 

       # Title of this report that will be displayed above the results
       - name: "example"
	 	 
         # Type of reports include
         # 1. list
         #       ROWS: caller method
         #       COLS: one column named after the sensor defined in "cols" 
         #       DATA: values from the sensor named in "cols" 
         # 2. compare
         #       ROWS: 
         #       COLS: uses the "cols" sensor values as column headers
         #       DATA: values from the sensor named in "cols" 
         # 3. table
         #       ROWS: 
         #       COLS: uses rule names for cols[0-n] as column headers - parses data values
         #       DATA: values from the sensor named in "cols" 
         # 4. series - table but each row starts with a timestamp (currently includes callers col too)
         #       ROWS: 
         #       COLS: uses rule names for cols[0-n] as column headers - parses data values
         #       DATA: values from the sensor named in "cols"
         type: "table"
       
         # Rows indicates a sensor to be used to populate row headers
         rows: "get-routes"
	   
         # Cols indicates a sensor (or list of sensors) to be used to populate column headers
         cols: "get-users"
   
         # Data indicates how the content of data cells should be populated. Can be a fixed string or a rule name.
         data: "X"
	   



## Building from Source

Should be as simple as
    
        $ mvn install
        
Then you can use the jot-x.x.jar in the target directory.

Contributions are welcome.  See the bugtracker to find issues to work on if you want to make JOT better.







## TO DO LIST
        
        - Solve problem of sensors inside JOT scope
          1) don't instrument JOT classes -- anything using shading
          2) use global scope to check anywhere you're inside a sensor call
        
        - Create JOT log file instead of system.out
        
        - New rules
          1) which routes are non-idempotent?
        
        - Sensors
          # future features - maybe think about reporting?
          # enabled: "false"
          # sample: "1000" # report every 1000 times? time frequency?
          # counter: "?"   # report 10 mins?
          # scope: include a capture and regex to say whether to start scope (if service.P0.getParameter=foobar)
          # exec: run this code.  before? after? during?
        
        - Reports 
          # possible additions to cols -- caller, stack[n], trace#

