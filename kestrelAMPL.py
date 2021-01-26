import os
import re
import xmlrpclib
import sys
import socket
import gzip
import base64
import StringIO
import tempfile

class kestrelAMPL:
  """
  kestrelAMPL class
    Sets up XML file for problem to submit to NEOS Server.
  """

  def __init__(self):
    (self.host,self.port) = self.getNEOSServer()
    (self.username,self.userpassword) = self.getAuthenticationOptions()
    self.email = self.getEmail()

    if not self.email:
      sys.stdout.write("An email address is required for NEOS submissions.\n")
      sys.stdout.write('To set: option email "<address>";\n\n')
      sys.exit(1)

    sys.stdout.write("Connecting to: {}:{}\n".format(self.host,self.port))
    self.neos = xmlrpclib.ServerProxy("https://{}:{}".format(self.host,self.port))
    try:
      result = self.neos.ping()
    except socket.error, e:
      sys.stderr.write("Error, NEOS solver is temporarily unavailable.\n")
      sys.exit(1)

  def tempfile(self):
    return os.path.join(tempfile.gettempdir(),'at{}.jobs'.format(os.getenv('ampl_id')))

  def kill(self,jobnumber,password):
    response = self.neos.killJob(jobNumber,password)
    sys.stdout.write(response+"\n")

  def retrieve(self,stub,jobNumber,password):

    # NEOS should return results as uu-encoded xmlrpclib.Binary data
    results = self.neos.getFinalResults(jobNumber,password)
    if isinstance(results,xmlrpclib.Binary):
      results = results.data

    #decode results to kestrel.sol
    # Well try to anyway, any errors will result in error strings in .sol file
    #  instead of solution.
    with open(stub + ".sol","wb") as solfile:
      solfile.write(results)

  def submit(self, xml):
    user = "{} on {}".format(os.getenv('LOGNAME'),socket.getfqdn(socket.gethostname()))
    if (self.username is None or self.userpassword is None):
      (jobNumber,password) = self.neos.submitJob(xml,user,"kestrel")
    else:
      (jobNumber,password) = self.neos.authenticatedSubmitJob(xml,self.username,self.userpassword, "kestrel")

    if jobNumber ==0:
      sys.stdout.write("Error: {}\nJob not submitted.\n".format(password))
      sys.exit(1)

    sys.stdout.write("Job {} submitted to NEOS, password='{}'\n".format(jobNumber,password))
    sys.stdout.write("Check the following URL for progress report :\n")
    sys.stdout.write("https://{}/neos/cgi-bin/nph-neos-solver.cgi?admin=results&jobnumber={}&pass={}\n".format(self.host,jobNumber,password))
    return (jobNumber,password)

  def getJobAndPassword(self):
    """
    If kestrel_options is set to job/password, then return
    the job and password values
    """
    jobNumber = 0
    password = ""
    options = os.getenv("kestrel_options")
    if options is not None:
      m = re.search(r'job\s*=\s*(\d+)',options,re.IGNORECASE)
      if m:
        jobNumber = int(m.groups()[0])
      m = re.search(r'password\s*=\s*(\S+)',options,re.IGNORECASE)
      if m:
        password = m.groups()[0]
    return (jobNumber,password)

  def getNEOSServer(self):
    """
    If neos_server is set to host[:port], then return
    the job and password values
    """
    host = "neos-server.org"
    port = "3333"
    options = ""

    if "neos_server" in os.environ.keys():
      options = os.getenv("neos_server")
    elif "NEOS_SERVER" in os.environ.keys():
      options = os.getenv("NEOS_SERVER")
    if options is not None:
      m = re.match('(\S+):(\d+)',options)
      if m:
        host = m.groups()[0]
        port = m.groups()[1]
      else:
        m = re.match('(\S+)',options)
        if m:
          host = m.groups()[0]
    return (host,port)

  def getEmail(self):
    """
    Get email provided by user.
    """
    email = ""

    if "email" in os.environ.keys():
      option = os.getenv("email")
    elif "EMAIL" in os.environ.keys():
      option = os.getenv("EMAIL")
    if option is not None:
      m = re.match(r'.+@.+\..+', option.strip())
      if m:
        email = option.strip()
    return email

  def getAuthenticationOptions(self):
    """
    If 'authenticate' is set to '"username","password"', then return
    the authentication options
    """
    username = None
    userpassword = None
    options = None

    if "neos_username" in os.environ.keys():
      options = os.getenv("neos_username")
    elif "NEOS_USERNAME" in os.environ.keys():
      options = os.getenv("NEOS_USERNAME")
    else:
      return (username,userpassword)

    if options is not None:
      m = re.match('(\S+)',options)
      if m:
        username = m.groups()[0]

    if "neos_user_password" in os.environ.keys():
      options = os.getenv("neos_user_password")
    elif "NEOS_USER_PASSWORD" in os.environ.keys():
      options = os.getenv("NEOS_USER_PASSWORD")
    else:
      return (username,userpassword)

    if options is not None:
      m = re.match('(\S+)',options)
      if m:
        userpassword = m.groups()[0]

    return (username,userpassword)

  def getSolverName(self):
    """
    Read in the kestrel_options to pick out the solver name.
    The tricky parts:
      we don't want to be case sensitive, but NEOS is.
      we need to read in options variable
    """

    # Get a list of available kestrel solvers from NEOS
    allKestrelSolvers = self.neos.listSolversInCategory("kestrel")
    kestrelAmplSolvers = []
    for s in allKestrelSolvers:
      i = s.find(':AMPL')
      if i > 0:
        kestrelAmplSolvers.append(s[0:i])
    self.options = None

    # Read kestrel_options to get solver name
    if "kestrel_options" in os.environ.keys():
      self.options = os.getenv("kestrel_options")
    elif "KESTREL_OPTIONS" in os.environ.keys():
      self.options = os.getenv("KESTREL_OPTIONS")

    if self.options is not None:
      m = re.search('solver\s*=*\s*(\S+)',self.options,re.IGNORECASE)
      NEOS_solver_name=None
      if m:
        solver_name=m.groups()[0]
        for s in kestrelAmplSolvers:
          if s.upper() == solver_name.upper():
            NEOS_solver_name=s
            break

        if not NEOS_solver_name:
          sys.stdout.write("{} is not available on NEOS.  Choose from:\n".format(solver_name))
          for s in kestrelAmplSolvers:
            sys.stdout.write("\t{}\n".format(s))
          sys.stdout.write('To choose: option kestrel_options "solver=xxx";\n\n')
          sys.exit(1)

    if self.options is None or m is None:
      sys.stdout.write("No solver name selected.  Choose from:\n")
      for s in kestrelAmplSolvers:
        sys.stdout.write("\t{}\n".format(s))
      sys.stdout.write('\nTo choose: option kestrel_options "solver=xxx";\n\n')
      sys.exit(1)

    return NEOS_solver_name

  def formXML(self,stub):
    """
    Create xml file for this problem
    """
    solver = self.getSolverName()
    zipped_nl_file = StringIO.StringIO()
    with open(stub+".nl","rb") as nlfile:
      zipper = gzip.GzipFile(mode='wb',fileobj=zipped_nl_file)
      zipper.write(nlfile.read())
      zipper.close()

    ampl_files={}
    for key in ['adj','col','env','fix','spc','row','slc','unv']:
      if os.access(stub+"."+key,os.R_OK):
        f = open(stub+"." +key,"r")
        val = ""
        buf = f.read()
        while buf:
          val += buf
          buf = f.read()
        f.close()
        ampl_files[key] = val

    # Get priority
    priority = ""
    m = re.search(r'priority[\s=]+(\S+)',self.options)
    if m:
      priority = "<priority>%s</priority>\n" % (m.groups()[0])

    # Add any AMPL-created environment variables to dictionary
    solver_options = "kestrel_options:solver=%s\n" % solver.lower()
    solver_options_key = "%s_options" % solver

    if solver_options_key in os.environ.keys():
      solver_options+="%s_options:%s\n"%(solver.lower(), os.getenv(solver_options_key))
    elif solver_options_key.lower() in os.environ.keys():
      solver_options+="%s_options:%s\n"%(solver.lower(), os.getenv(solver_options_key.lower()))
    elif solver_options_key.upper() in os.environ.keys():
      solver_options+="%s_options:%s\n"%(solver.lower(), os.getenv(solver_options_key.upper()))

    xml = """
          <document>
          <category>kestrel</category>
          <solver>%s</solver>
          <inputType>AMPL</inputType>
          <email>%s</email>
          %s
          <solver_options>%s</solver_options>
          <nlfile><base64>%s</base64></nlfile>\n""" %\
                            (solver,self.email,priority,
                             solver_options,
                             base64.encodestring(zipped_nl_file.getvalue()))

    for key in ampl_files.keys():
      xml += "<%s><![CDATA[%s]]></%s>\n" % (key,ampl_files[key],key)

    for option in ["kestrel_auxfiles","mip_priorities","objective_precision"]:
      if option in os.environ.keys():
        xml += "<%s><![CDATA[%s]]></%s>\n" % (option,os.getenv(option),option)

    xml += "</document>"
    return xml
