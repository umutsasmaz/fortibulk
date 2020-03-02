import paramiko
from paramiko_expect import SSHClientInteraction
from getpass import getpass
from tqdm import tqdm
from art import *


def fwPolicyImport():
    try:
        with open('policy.txt') as p:
            content = p.readlines()
        pList = [i.strip() for i in content]
        policyObjects = []
        for i in pList:
            policy = i.split(',')
            if len(policy) == 3:
                policyObjects.append(forti.firewallPolicy(policy[0], policy[1], policy[2]))
            elif len(policy) == 4:
                policyObjects.append(forti.firewallPolicy(policy[0], policy[1], policy[2], policy[3]))
            elif len(policy) == 5:
                policyObjects.append(forti.firewallPolicy(policy[0], policy[1], policy[2], policy[3], policy[4]))
            elif len(policy) == 6:
                policyObjects.append(
                    forti.firewallPolicy(policy[0], policy[1], policy[2], policy[3], policy[4], policy[5]))
            elif len(policy) == 7:
                policyObjects.append(
                    forti.firewallPolicy(policy[0], policy[1], policy[2], policy[3], policy[4], policy[5], policy[6]))
            elif len(policy) == 8:
                policyObjects.append(
                    forti.firewallPolicy(policy[0], policy[1], policy[2], policy[3], policy[4], policy[5], policy[6],
                                         policy[7]))
            else:
                policyObjects.append(
                    forti.firewallPolicy(policy[0], policy[1], policy[2], policy[3], policy[4], policy[5], policy[6],
                                         policy[7], policy[8]))
        return policyObjects

    except Exception as e:
        print('policy.txt file could not be found!')


def fwServiceImport():
    try:
        with open('services.txt') as s:
            content = s.readlines()
        serviceList = [i.strip() for i in content]
        serviceObjects = []
        for i in serviceList:
            service = i.split('_')
            a = forti.firewallService(i, service[0].lower(), service[1])
            serviceObjects.append(a)
        return serviceObjects
    except Exception as e:
        print('services.txt file could not be found!')


def fwAdressImport():
    try:
        with open('addresses.txt') as a:
            content = a.readlines()
        adressList = [i.strip() for i in content]
        addressObjects = []
        for i in adressList:
            a = forti.firewallAddress(i)
            addressObjects.append(a)
        return addressObjects

    except Exception as e:
        print('addresses.txt file could not be found!')


def connectToFirewall():

    fw_info = forti.takeCredentials()
    fw_adresses = fwAdressImport()
    fw_services = fwServiceImport()
    fw_policies = fwPolicyImport()


    if fw_adresses == None and fw_services == None and fw_policies == None:
        print('Please prepare .txt files first!')
        exit()

    #connection info
    fw_ip = fw_info.firewall
    fw_username = fw_info.username
    fw_password = fw_info.password
    fw_vdom = fw_info.vdom

    #checkpoint
    firewall_prompt = '.*# '

    #firewall SSH object
    ssh_fw = paramiko.SSHClient()

    #Known host & RSA key
    ssh_fw.load_system_host_keys()
    ssh_fw.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    #connection to firewall
    try:
        ssh_fw.connect(hostname=fw_ip,username=fw_username,password=fw_password,port=22)
        print('\nConnected to firewall!')
        with SSHClientInteraction(ssh_fw,timeout=15,display=False,buffer_size=65535) as forti_fw:
            try:
                forti_fw.send('\n')
                forti_fw.expect(firewall_prompt)
                if fw_vdom != 'global':
                    forti_fw.send('config vdom')
                    forti_fw.expect(firewall_prompt, timeout=5)
                    forti_fw.send('edit {}'.format(fw_vdom))
                    forti_fw.expect(firewall_prompt)

                    if fw_adresses != None:
                        #creating firewall adress objects
                        forti_fw.send('config firewall address')
                        forti_fw.expect(firewall_prompt)
                        print("Starting creation of adress objects!")
                        for i in tqdm(fw_adresses,unit=" address"):
                            forti_fw.send('edit {}'.format(i))
                            forti_fw.expect(firewall_prompt)
                            forti_fw.send('set subnet {}'.format(i))
                            forti_fw.expect(firewall_prompt)
                            forti_fw.send('next')
                            forti_fw.expect(firewall_prompt)
                        forti_fw.send('end')
                        forti_fw.expect(firewall_prompt)

                    if fw_services != None:
                        #creating services
                        forti_fw.send('config firewall service custom')
                        forti_fw.expect(firewall_prompt)
                        print("Starting creation of service objects!")
                        for i in tqdm(fw_services,unit=" service"):
                            forti_fw.send('edit {}'.format(i.servicename))
                            forti_fw.expect(firewall_prompt)
                            if i.protocol == 'tcp':
                                forti_fw.send('set tcp-portrange {}'.format(i.portnumber))
                            else:
                                forti_fw.send('set udp-portrange {}'.format(i.portnumber))
                            forti_fw.expect(firewall_prompt)
                            forti_fw.send('next')
                            forti_fw.expect(firewall_prompt)
                        forti_fw.send('end')
                        forti_fw.expect(firewall_prompt)

                    if fw_policies != None:
                        #creating policies
                        forti_fw.send('config firewall policy')
                        forti_fw.expect(firewall_prompt)
                        print("Starting creation of policies!")
                        for i in tqdm(fw_policies,unit=" policy"):
                            forti_fw.send('edit 0')
                            forti_fw.expect(firewall_prompt)
                            forti_fw.send('set srcintf {}'.format(i.srcintf))
                            forti_fw.expect(firewall_prompt)
                            forti_fw.send('set dstintf {}'.format(i.dstintf))
                            forti_fw.expect(firewall_prompt)
                            forti_fw.send('set srcaddr {}'.format(i.srcaddr))
                            forti_fw.expect(firewall_prompt)
                            forti_fw.send('set dstaddr {}'.format(i.dstaddr))
                            forti_fw.expect(firewall_prompt)
                            forti_fw.send('set service {}'.format(i.service))
                            forti_fw.expect(firewall_prompt)
                            forti_fw.send('set comments {}'.format(i.comment))
                            forti_fw.expect(firewall_prompt)
                            forti_fw.send('set schedule {}'.format(i.schedule))
                            forti_fw.expect(firewall_prompt)
                            forti_fw.send('set action {}'.format(i.action))
                            forti_fw.expect(firewall_prompt)
                            forti_fw.send('set status {}'.format(i.status))
                            forti_fw.expect(firewall_prompt)
                            forti_fw.send('next')
                            forti_fw.expect(firewall_prompt)
                        forti_fw.send('end')
                        forti_fw.expect(firewall_prompt)
                    return

                if fw_adresses != None:
                    # Without vdom part
                    #creating firewall address objects
                    forti_fw.send('config firewall address')
                    forti_fw.expect(firewall_prompt)
                    print("Starting creation of adress objects!")
                    for i in tqdm(fw_adresses, unit=" address"):
                        forti_fw.send('edit {}'.format(i))
                        forti_fw.expect(firewall_prompt)
                        forti_fw.send('set subnet {}'.format(i))
                        forti_fw.expect(firewall_prompt)
                        forti_fw.send('next')
                        forti_fw.expect(firewall_prompt)
                    forti_fw.send('end')
                    forti_fw.expect(firewall_prompt)

                if fw_services != None:
                    # creating services
                    forti_fw.send('config firewall service custom')
                    forti_fw.expect(firewall_prompt)
                    print("Starting creation of service objects!")
                    for i in tqdm(fw_services, unit=" service"):
                        forti_fw.send('edit {}'.format(i.servicename))
                        forti_fw.expect(firewall_prompt)
                        if i.protocol == 'tcp':
                            forti_fw.send('set tcp-portrange {}'.format(i.portnumber))
                        else:
                            forti_fw.send('set udp-portrange {}'.format(i.portnumber))
                        forti_fw.expect(firewall_prompt)
                        forti_fw.send('next')
                        forti_fw.expect(firewall_prompt)
                    forti_fw.send('end')
                    forti_fw.expect(firewall_prompt)
                if fw_policies != None:
                    # creating policies
                    forti_fw.send('config firewall policy')
                    forti_fw.expect(firewall_prompt)
                    print("Starting creation of policies!")
                    for i in tqdm(fw_policies, unit=" policy"):
                        forti_fw.send('edit 0')
                        forti_fw.expect(firewall_prompt)
                        forti_fw.send('set srcintf {}'.format(i.srcintf))
                        forti_fw.expect(firewall_prompt)
                        forti_fw.send('set dstintf {}'.format(i.dstintf))
                        forti_fw.expect(firewall_prompt)
                        forti_fw.send('set srcaddr {}'.format(i.srcaddr))
                        forti_fw.expect(firewall_prompt)
                        forti_fw.send('set dstaddr {}'.format(i.dstaddr))
                        forti_fw.expect(firewall_prompt)
                        forti_fw.send('set service {}'.format(i.service))
                        forti_fw.expect(firewall_prompt)
                        forti_fw.send('set comments {}'.format(i.comment))
                        forti_fw.expect(firewall_prompt)
                        forti_fw.send('set schedule {}'.format(i.schedule))
                        forti_fw.expect(firewall_prompt)
                        forti_fw.send('set action {}'.format(i.action))
                        forti_fw.expect(firewall_prompt)
                        forti_fw.send('set status {}'.format(i.status))
                        forti_fw.expect(firewall_prompt)
                        forti_fw.send('next')
                        forti_fw.expect(firewall_prompt)
                    forti_fw.send('end')
                    forti_fw.expect(firewall_prompt)
                    return
            except Exception as e:
                pass
    except Exception as e:
        print('Check the credentials to connect!')

class forti(object):

    def __init__(self,firewall,username,password,vdom):
        self.firewall = firewall
        if vdom != "":
            self.vdom = vdom
        else:
            self.vdom = 'global'
        self.username = username
        self.password = password

    def __repr__(self):
        return 'Firewall : {} \n Username: {} \n Password : {} \n Vdom : {} '.format(self.firewall, self.username,
                                                                                     self.password, self.vdom)

    @classmethod
    def takeCredentials(cls):

        try:
            umutsasmaz = text2art('''Fortibulk''',font='small')
            print('-' * 50 + '\n')
            print(umutsasmaz)
            print('Press Enter after you type the requested info! \n')
            print('-' * 50 + '\n')

        except Exception as u:
            pass
        while True:
            cls.firewall = input('Please enter firewall ip address : ')
            while not cls.firewall:
                cls.firewall = input('Please enter firewall ip address : ')
            cls.username = input('Please enter username : ')
            while not cls.username:
                cls.username = input('Please enter username : ')
            cls.password = getpass('Please enter password : ')
            cls.vdom = input('Please enter vdom name if any, leave it blank to global : ')

            print('-' * 70 + '\n')
            approve = int(input('\n If you want to start with this info press 1 else press any key and Enter : '))
            if approve == 1:
                break
            else:
                continue
        return cls(firewall=cls.firewall, username=cls.username, password=cls.password,vdom=cls.vdom)

    class firewallPolicy(object):

        def __init__(self ,srcaddr,dstaddr,service,comment=None,srcintf='any',dstintf='any',schedule='always',action='accept',status='enable'):

            self.srcintf = srcintf
            self.dstintf = dstintf
            self.srcaddr = srcaddr
            self.dstaddr = dstaddr
            self.schedule = schedule
            self.service = service
            self.comment = comment
            self.action = action
            self.status = status

        def __repr__(self):
            return 'Source interface : {} \n Destination interface : {} \n Source address : {} \n Destination address : {} \n Schedule : {} \n Service : {} \n Action : {} \n Status : {} '.format(self.srcintf,self.dstintf,self.srcaddr,self.dstaddr,self.schedule,self.service,self.action,self.status)
    class firewallAddress(object):

        def __init__(self,address):
            self.address = address
        def __str__(self):
            return self.address


    class firewallService(object):

        def __init__(self,servicename,protocol,portnumber):
            self.servicename = servicename
            self.protocol = protocol
            self.portnumber = portnumber

        def __repr__(self):
            return 'Service name : {} \n Protocol : {} \n Port Number : {} '.format(self.servicename,self.protocol,self.portnumber)

if __name__ == '__main__':

    connectToFirewall()