import sys
import time
import json
import cloudpassage


class HaloGeneral(object):
    """This class wraps Halo API functionality."""
    def __init__(self, config):
        """Pass in a remove_old_kernels.ConfigHelper
        object on instantiation."""
        self.check_api_credentials(config)

        # authenticate to get a session object
        self.session = cloudpassage.HaloSession(config.halo_key,
                                                config.halo_secret)

        return

    ##
    #
    #   Check to see if we have the proper env vars set
    #
    #   Parameters:
    #
    #       Halo General Object (object)
    #       Config Helper Object (object)
    #
    ##

    def check_api_credentials(self, config):
        halo_api_key = "HALO_API_KEY"
        halo_secret = "HALO_API_SECRET_KEY"
        ERROR = 1

        if config.halo_key is None:
            print "The environment variable %s is not set" % halo_api_key
            sys.exit(ERROR)

        if config.halo_secret is None:
            print "The environment variable %s is not set" % halo_secret
            sys.exit(ERROR)

    #########################
    #
    #   Server related methods
    #
    #########################

    ##
    #
    #   Get a Server object
    #
    #   Parameters:
    #
    #       Halo General object (object)
    #
    #   Return:
    #
    #       list_of_servers (list) - returns a list of servers
    #
    ##

    def get_server_obj(self):
        server_obj = cloudpassage.Server(self.session)

        return server_obj

    ##
    #
    #   List all servers
    #
    #   Parameters:
    #
    #       Halo General object (object)
    #
    #   Return:
    #
    #       Server Object (object)
    #
    ##

    def list_all_servers(self):
        list_of_servers = self.server_obj.list_all()

        return list_of_servers

    #########################
    #
    #   Server Group related methods
    #
    #########################

    ##
    #
    #   Get a Server Group object
    #
    #   Parameters:
    #
    #       Halo General object (object)
    #
    #   Return:
    #
    #       Server Group Object (object)
    #
    ##

    def get_server_group_obj(self):
        server_group_obj = cloudpassage.ServerGroup(self.session)

        return server_group_obj

    ###
    #    List all server groups
    #
    #    Parameters:
    #
    #        self - class object
    #        server_group_obj - object of server group class
    #
    #    Return:
    #       list of server groups (list)
    #
    ###

    def list_all_server_groups(self, server_group_obj):
        server_groups = server_group_obj.list_all()

        return server_groups

    ###
    #   List all servers in a server group
    #
    #   Parameters -
    #
    #       server_group_obj (object) - server group object
    #       server_group_id (str) - id of server group
    #
    #    Return -
    #
    #       list of servers in groups (list) - list of servers in group
    #
    ###

    def list_all_servers_in_group(self, server_group_obj, server_group_id):
        list_of_servers = server_group_obj.list_members(server_group_id)

        return list_of_servers

    ##
    #
    #   Get a server group ID by server group name
    #
    #   Parameters -
    #
    #       server_group_obj (object) - server group object
    #       server_group_name (str) - name of server group
    #
    #    Return -
    #
    #       server_group_id (str) - server group ID
    #
    ###

    def get_server_group_id_by_name(self, server_group_obj,
                                    server_group_name):
        server_groups = self.list_all_server_groups(server_group_obj)
        server_group_id = None

        for server_group in server_groups:
            if server_group["tag"] == server_group_name:
                server_group_id = server_group["id"]
                break

        return server_group_id

    ##
    #
    #   Get the LIDS policy IDs for a server group
    #
    #       Parameters:
    #
    #           self (object) - Halo General object
    #           server_group_obj (object) - Server Group object (object)
    #           server_group_id (str) - Server group id
    #
    #       Return:
    #
    #           response["lids_policy_ids"] (dict) - dictionary of IDs
    #
    ##

    def get_server_group_lids_policy_ids(self, server_group_obj,
                                         server_group_id):
        response = server_group_obj.describe(server_group_id)

        return response["lids_policy_ids"]

    ##
    #
    #   Get the FIM policy IDs for a server group
    #
    #   Parameters:
    #       self (object) Halo General object
    #       server_group_obj (object) - server group object
    #       server_group_id (str) - server group id
    #
    #   Return:
    #
    #      response["fim_policy_ids"] (list) - list of FIM policy IDs
    #
    ##

    def get_server_group_fim_policy_ids(self, server_group_obj,
                                        server_group_id):
        response = server_group_obj.describe(server_group_id)

        return response["fim_policy_ids"]

    ##
    #
    #   Update a server group with a new FIM policy
    #
    #   Parameters:
    #       self (object) Halo General object
    #       server_group_obj (object) - server group object
    #       policy_key (str) - key to tell API the type of policy
    #       policy_id (str) - the policy id
    #       server_group_id (str) - server group id
    #
    ##

    def update_server_group_fim_policy_ids(self, server_group_obj,
                                           policy_id, server_group_id):
        policy_ids = [policy_id]

        server_group_obj.update(server_group_id,
                                linux_fim_policy_ids=policy_ids)

        return

    ##
    #
    #   Update a server group with a new LIDS policy
    #
    #   Parameters:
    #       self (object) Halo General object
    #       server_group_obj (object) - server group object
    #       policy_key (str) - key to tell API the type of policy
    #       policy_id (str) - the policy id
    #       server_group_id (str) - server group id
    #
    ##

    def update_server_group_lids_policy_ids(self, server_group_obj,
                                            policy_id, server_group_id):
        policy_ids = [policy_id]

        server_group_obj.update(server_group_id, lids_policy_ids=policy_ids)

        return

    ###################
    #
    #   FIM policy related methods
    #
    ###################

    ##
    #
    #   Get a FIM policy object
    #
    #   Parameters:
    #
    #       Halo General object (object)
    #
    #   Return:
    #
    #       Fim Policy Object (object)
    #
    ##

    def get_fim_policy_obj(self):
        fim_policy_obj = cloudpassage.FimPolicy(self.session)

        return fim_policy_obj

    ##
    #
    #   Get the details of a FIM policy
    #
    #   Parameters:
    #
    #       self (object) - Halo General object
    #       fim_policy_obj (object) - FIM policy object
    #       fim_policy_file_path (str) - FIM policy ID
    #
    #   Return:
    #       response (dict) - detailed configuration information of policy
    #
    ##

    def create_fim_policy(self, fim_policy_obj, fim_policy_file_path):
        ERROR = 1

        fim_policy_id = None

        with open(fim_policy_file_path) as json_file:
            json_data = json.load(json_file)

        try:
            fim_policy_id = fim_policy_obj.create(json_data)
        except cloudpassage.CloudPassageValidation as error:
            print "%s - it appears there may be a workflow issue, exiting..."\
                  % error
            sys.exit(ERROR)

        return fim_policy_id

    ##
    #
    #   Get the details of a FIM policy
    #
    #   Parameters:
    #
    #       self (object) - Halo General object
    #       fim_policy_obj (object) - FIM policy object
    #       policy_id (str) - FIM policy ID
    #
    #   Return:
    #       response (dict) - detailed configuration information of policy
    #
    ##

    def get_fim_policy_configuration(self, fim_policy_obj, policy_id):
        response = fim_policy_obj.describe(policy_id)

        return response

    ####################
    #
    #   FIM Baseline related methods
    #
    ####################

    ##
    #
    #   Get a FIM Baseline object
    #
    #   Parameters:
    #       self - HaloGeneral Object (object)
    #
    #   Return
    #
    #       fim_baseline_obj - FIM Baseline Object (object)
    #
    ##

    def get_fim_baseline_obj(self):
        fim_baseline_obj = cloudpassage.FimBaseline(self.session)

        return fim_baseline_obj

    ##
    #
    #   Create a FIM Baseline for a target workload
    #
    #   Parameters:
    #
    #       self - HaloGeneral Object (object)
    #       fim_baseline_obj - FIM Baseline Object (object)
    #       fim_policy_id - FIM Policy ID (str)
    #       server_id - Server ID (str)
    #
    #   Return:
    #
    #       fim_baseline_id (str) - FIM baseline ID
    ##

    def create_fim_baseline(self, fim_baseline_obj, fim_policy_id, server_id):
        fim_baseline_id = fim_baseline_obj.create(fim_policy_id, server_id)

        self.wait_for_fim_baseline_activation(fim_baseline_obj, fim_policy_id)

        return fim_baseline_id

    ##
    #
    #   Delete a FIM baseline
    #
    #   Parameters:
    #
    #
    ##

    def delete_fim_baseline(self, fim_baseline_obj, fim_policy_id,
                            fim_baseline_id):

        fim_baseline_obj.delete(fim_policy_id, fim_baseline_id)

        return

    ##
    #
    #   Check until a FIM Baseline is active
    #
    #   Parameters:
    #
    #       HaloGeneral Object (object)
    #       FIM Baseline Object (object)
    #       FIM Policy ID (str)
    #
    ##

    @classmethod
    def wait_for_fim_baseline_activation(self, fim_baseline_obj,
                                         fim_policy_id):
        baseline_status = ""
        desired_status = "Active"
        INCREMENTOR = 1
        SLEEP_TIME = 30

        while baseline_status != desired_status:
            counter = 0
            baseline_status = "Active"
            results = fim_baseline_obj.list_all(fim_policy_id)
            print "Checking if baseline is active...\n"
            for index in results:
                baseline_status = results[counter]["status"]
                if baseline_status != desired_status:
                    baseline_status = results[counter]["status"]
                    print "Baseline is %s... will check again shortly...\n"\
                          % baseline_status
                    time.sleep(SLEEP_TIME)
                    break
                counter = counter + INCREMENTOR
        print "Baseline is active...\n"

        return

    ##
    #
    #   List all baselines for a FIM policy
    #
    #   Parameters:
    #       HaloGeneral Object (object)
    #       FIM Policy Object (object)
    #       FIM Policy ID (str)
    #
    #   Return:
    #
    #       List of FIM Policies (list)
    #
    ##

    def list_all_fim_baselines(self, fim_baseline_obj, fim_policy_id):
        fim_policies = fim_baseline_obj.list_all(fim_policy_id)

        return fim_policies

    ########################
    #
    #   HTTP Helper related methods
    #
    ########################

    ##
    #
    #   Get an HTTP helper object - to make calls to the REST endpoints
    #
    #   Parameters:
    #
    #       self (object) - HaloGeneral object
    #
    #   Return:
    #
    #      http_helper_obj (object) - HTTP helper object
    #
    ##

    def get_http_helper_obj(self):
        http_helper_obj = cloudpassage.HttpHelper(self.session)

        return http_helper_obj

    ##
    #
    #   Get a server ID for an IP
    #
    #   Parameters:
    #
    #       self (object) - HaloGeneral object
    #       http_helper_obj (object) - HTTP helper object
    #       baseline_host_ip (str) - baseline host IP
    #
    #   Return:
    #
    #      response["servers"][FIRST_SERVER]["id"] (str) - Server ID
    #
    ##

    def get_server_id_for_ip(self, http_helper_obj, baseline_host_ip):
        FIRST_SERVER = 0

        # endpoint url for servers API
        endpoint_url = '/v1/servers?connecting_ip_address=%s'\
                       % baseline_host_ip

        response = http_helper_obj.get(endpoint_url)

        return response["servers"][FIRST_SERVER]["id"]

    ########################
    #
    #   Scan related methods
    #
    ########################

    ##
    #
    #   Get a Scan object - to make calls to the REST endpoints
    #
    #   Parameters:
    #
    #       self (object) - HaloGeneral object
    #
    #   Return:
    #
    #      scan_obj (object) - Scan object
    #
    ##

    def get_scan_obj(self):
        scan_obj = cloudpassage.Scan(self.session)

        return scan_obj

    ###
    #
    #    Initialize a scan on a workload
    #
    #    Parameters:
    #
    #       self (object) - HaloGeneral object
    #       server_id (str) - ID of the server to be scanned
    #       scan_type (str) - fim, csm or sva
    #
    #    Return:
    #       response (dict) - dictionary with details of command or exception
    #
    ###

    def scan_server(self, scan_obj, server_id, scan_type):
        response = scan_obj.initiate_scan(server_id, scan_type)

        return response

    ###
    #
    #    Get the last scan results
    #
    #    Parameters:
    #
    #       self (object) - HaloGeneral object
    #       server_id (str) - ID of the server to be scanned
    #       scan_type (str) - fim, csm or sva
    #
    #    Return:
    #       scan_results (dict) - dictionary with details of command
    #       or exception
    #
    ###

    def get_last_scan_results(self, scan_obj, server_id, scan_type):
        scan_results = scan_obj.last_scan_results(server_id, scan_type)

        return scan_results

    ###
    #
    #    Get scan findings - for example files that changed in a FIM scan
    #
    #    Parameters:
    #
    #       self (object) - HaloGeneral object
    #       scan_obj (object) - Scan object
    #       scan_id (str) - Scan ID
    #       findings_id (str) - findings ID
    #
    #    Return:
    #       scan_results (dict) - dictionary with details of scan
    #
    ###

    def get_scan_findings(self, scan_obj, scan_id, findings_id):
        response = scan_obj.findings(scan_id, findings_id)

        return response

    ###
    #
    #    Get scan details
    #
    #    Parameters:
    #
    #       self (object) - HaloGeneral object
    #       scan_obj (object) - Scan object
    #       scan_id (str) - Scan ID
    #
    #    Return:
    #       response (dict) - dictionary with details of scan
    #
    ###

    def get_scan_details(self, scan_obj, scan_id):
        response = scan_obj.scan_details(scan_id)

        return response

    #########################
    #
    #   LIDS policy related methods
    #
    #########################

    ##
    #
    #   Gets a lids policy object
    #
    #   Parameters:
    #
    #       Halo General Object (object)
    #
    #   Return:
    #
    #       Lids policy object (object)
    #
    ##

    def get_lids_policy_obj(self):
        lids_policy_obj = cloudpassage.LidsPolicy(self.session)

        return lids_policy_obj

    ##
    #
    #   Create a lids policy
    #
    #   Parameters:
    #
    #       self (object) - Halo General Object
    #       lids_policy_obj (object) - LIDS policy object
    #       lids_policy_file_path (str) - path to LIDS policy
    #
    #   Return:
    #
    #       lids_policy_id (str) - Lids policy ID
    #
    ##

    def create_lids_policy(self, lids_policy_obj, lids_policy_file_path):
        ERROR = 1

        lids_policy_id = None

        with open(lids_policy_file_path) as json_file:
            json_data = json.load(json_file)

        try:
            lids_policy_id = lids_policy_obj.create(json_data)
        except cloudpassage.CloudPassageValidation as error:
            print "%s - it appears there may be a workflow issue, exiting..."\
                  % error
            sys.exit(ERROR)

        return lids_policy_id

    ##
    #
    #   Update a LIDS policy using the SDK method or HttpHelper with REST
    #
    #       Parameters:
    #           self (object) - Halo General object
    #           lids_policy_obj (object) - LIDS policy object
    #           http_helper_obj (object) - HTTP Helper object
    #           lids_policy_id (str) - LIDS policy ID
    #           lids_policy_file_path (str) - LIDS policy file path
    #
    ##

    def update_lids_policy(self, object, lids_policy_id,
                           lids_policy_file_path):

        with open(lids_policy_file_path) as json_file:
            json_data = json.load(json_file)

        try:
            # if the SDK is used - there appears to be a defect in the
            # Policy.py in update I had to change the method signature
            # and comment out a line to get it to work - looking into it.
            # Add rest call too until sorted so nobody has to change SDK code
            if isinstance(object, cloudpassage.LidsPolicy):
                lids_policy_object = object
                lids_policy_object.update(lids_policy_id,
                                          json_data)
            elif isinstance(object, cloudpassage.HttpHelper):
                http_helper_object = object
                endpoint_url = "/v1/lids_policies/%s" % lids_policy_id

                http_helper_object.put(endpoint_url, json_data)
        except cloudpassage.exceptions.CloudPassageValidation as e:
            print "Validation exception - check the json in the update call."\
                  "\n\n%s" % e
        return

    ##
    #
    #   Get the LIDS policy configuration
    #
    #       Parameters:
    #
    #           self (object) - Halo General object
    #           lids_policy_obj (object) - LIDS policy object (object)
    #           policy_id (str) - LIDS policy id
    #
    ##

    def get_lids_policy_configuration(self, lids_policy_obj, policy_id):
        response = lids_policy_obj.describe(policy_id)

        return response

        # checks the status of an API command

    ##
    #
    #   Check the status of an API call
    #
    #       Parameters:
    #
    #           self (object) - Halo General object
    #           server_obj (object) - Server object
    #           server_id (str) - server ID
    #           command_id (str) - command ID
    #
    #       Return:
    #
    #           response (dict) - command status
    ##

    @classmethod
    def check_api_call_status(self, server_obj, server_id, command_id):
        # responses come back with heartbeats so need to wait
        delay = 30

        time.sleep(delay)
        response = cloudpassage.Server.command_details(server_obj,
                                                       server_id, command_id)

        return response

    ##
    #
    #   Monitor the state of an API call
    #
    #       Parameters:
    #
    #           self (object) - Halo General object
    #           server_id (str) - server ID
    #           response (dict) - command details response
    #
    #       Return:
    #
    #           ret_val (int) - return value
    #
    ##

    def process_api_request(self, server_id, response):
        QUEUED = "queued"
        PENDING = "pending"
        FAILED = "failed"
        STARTED = "started"
        STATUS = "status"
        RESULT = "result"

        ret_val = 0

        # get command ID then check until command finishes
        command_id = response["id"]
        server_obj = self.get_server_obj()
        response = cloudpassage.Server.command_details(server_obj,
                                                       server_id, command_id)

        while response[STATUS] == QUEUED or response[STATUS] == PENDING \
                or response[STATUS] == STARTED:
            print 'Command status is %s... waiting for next heartbeat...' \
                  % response[STATUS]
            response = self.check_api_call_status(server_obj, server_id,
                                                  command_id)

        if response[STATUS] == FAILED:
            errorMessage = response[RESULT]
            print "Command failed on host with %s" % errorMessage
            ret_val = 1

        return ret_val
