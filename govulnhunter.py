#!/usr/bin/env python3
'''
This command will gather all the vulnerabilities for a given GOLANG 
Module and display them for the user.
Run this program and provide it with the folder containing the go.mod
file. It will run for a bit and spit out a list of the vulnerable 
module paths that GO is reporting. You may find multiple versions
of the same module, this is normal and a feature of GO, or so I've 
read.
'''
import sys
import json
import xml.etree.ElementTree as ET
import urllib.request
import subprocess
import re

def findPackagePath(path, packagename, deps, packpath):
    for d in deps:
        if packagename in deps[d]:
            packpath.append(d)
            if 'crunchy' not in d:
                findPackagePath(path, d, deps, packpath)
            return    
    return
	
def getModWhy(path, packagename, version, deps):
    p = subprocess.run(['go', 'mod', 'why', packagename], cwd=path, capture_output=True)
    rc = p.returncode
    stdout = p.stdout.decode('utf-8')
    if rc == 0:
        if 'main module does not need package' in stdout:
            packpath = ['{}@{}'.format(packagename, version)]
            findPackagePath(path, packpath[0], deps, packpath)
            packpath = packpath[::-1]
            return packpath
        else:
            whypath = stdout.split('\n')[:-1]
            #Also use this method to get specifics
            packpath = ['{}@{}'.format(packagename, version)]
            findPackagePath(path, packpath[0], deps, packpath)
            packpath = packpath[::-1]
            return whypath + ['{CUSTOM}'] + packpath
            
#load packages
def loadPackages(path):
    p = subprocess.run(['go', 'mod', 'graph'], cwd=path, capture_output=True)
    rc = p.returncode
    stdout = p.stdout
    deps = {}
    stdout.decode('utf-8').split('\n')
    for line in stdout.decode('utf-8').split('\n'):
        if len(line) > 0:
            toks = line.split()
            if len(toks) != 2:
                print('>' + line)
                return
            if toks[0] in deps:
                deps[toks[0]].append(toks[1])
            else:
                deps[toks[0]] = [toks[1]]
    return deps
	
#get vulnerabilities
def getVulns():
    vulns = {}
    URL = 'https://vuln.go.dev/'
    with urllib.request.urlopen(URL) as response:
        namespace = '{{http://doc.s3.amazonaws.com/2006-03-01}}{}'
        xmlResp = response.read()    
        rt = ET.fromstring(xmlResp)
        for vuln in rt.findall(namespace.format('Contents')):
            key = vuln.find(namespace.format('Key')).text                           #key = vuln.find('{http://doc.s3.amazonaws.com/2006-03-01}Key').text
            Generation = vuln.find(namespace.format('Generation')).text             #Generation = vuln.find('{http://doc.s3.amazonaws.com/2006-03-01}Generation').text
            MetaGeneration = vuln.find(namespace.format('MetaGeneration')).text     #MetaGeneration = vuln.find('{http://doc.s3.amazonaws.com/2006-03-01}MetaGeneration').text
            LastModified = vuln.find(namespace.format('LastModified')).text         #LastModified = vuln.find('{http://doc.s3.amazonaws.com/2006-03-01}LastModified').text
            ETag = vuln.find(namespace.format('ETag')).text                         #ETag = vuln.find('{http://doc.s3.amazonaws.com/2006-03-01}ETag').text
            Size = vuln.find(namespace.format('Size')).text                         #Size = vuln.find('{http://doc.s3.amazonaws.com/2006-03-01}Size').text
            """
            <Contents>
              <Key>ID/GO-2020-0001.json</Key>
              <Generation>1645216880149137</Generation>
              <MetaGeneration>1</MetaGeneration>
              <LastModified>2022-02-18T20:41:20.230Z</LastModified>
              <ETag>"6c2cb2d1431d6952c4f2ac69f2e147bc"</ETag>
              <Size>768</Size>
            </Contents>
            """
            with urllib.request.urlopen(URL + key) as respJson:
                jsonResp = respJson.read()
                js = json.loads(jsonResp)
                if 'id' in js:
                    id = js['id']    #string
                    published = js['published']  #string
                    modified = js['modified']   #string
                    details = js['details']    #string
                    affecteds = js['affected']   #array
                    references = js['references'] #array
                    for affected in affecteds:
                        package = affected['package']
                        packagename = package['name']
                        ranges = affected['ranges']
                        database_specific = affected['database_specific']
                        ecosystem_specific = affected['ecosystem_specific']
                        name = package['name']
                        introduced = '(unknown)'
                        fixed = '(unknown)'
                        for rng in ranges:
                            rangetype = rng['type']
                            events = rng['events']
                            for evnt in events:
                                if 'introduced' in evnt:
                                    introduced = evnt['introduced']
                                elif 'fixed' in evnt:
                                    fixed = evnt['fixed']
                                else:
                                    print('unknown event {}'.format(evnt))
                        if len(ranges) > 1:
                            print('Not currently handling more than one range. Results in doubt.')
                        adding = [key, introduced, fixed]
                        if packagename in vulns:
                            vulns[packagename].append(adding) #key)
                        else:
                            vulns[packagename] = [adding] #key]
    return vulns
	
def getVersionAsNumber(versionStr):
    MAJMINREV = [r'^v?[0-9]+\.[0-9]+\.[0-9]+(\+incompatible)?$', 
                 r'v?([0-9]+)\.([0-9]+)\.([0-9]+)']
    NOSTART = [r'^0$', 
               r'(0)']  
    NOVERNOTAG = [r'^v?[0-9]+\.[0-9]+\.[0-9]+-[0-9]{14}-[0-9a-f]{12}$', 
                  r'v?([0-9]+)\.([0-9]+)\.([0-9]+)-([0-9]{14})-[0-9a-f]{12}']
    VERTAG = [r'^v?[0-9]+\.[0-9]+\.[0-9]+\-[0-9]+\.[0-9]{14}-[0-9a-f]{12}$', 
              r'v?([0-9]+)\.([0-9]+)\.([0-9]+)\-([0-9]+)\.([0-9]{14})-[0-9a-f]{12}']
    UNKNOWN = [r'^\(unknown\)$', 
               r'\(unknown\)']
    major = minor = subminor = taglevel = tagdate = 0
    if re.match(NOSTART[0], versionStr):     #'0'
        pass
    elif re.match(UNKNOWN[0], versionStr):     #'0'
        pass
        major = minor = subminor = '99'
    elif re.match(MAJMINREV[0], versionStr): #'v1.4.0' '1.6.0'
        major, minor, subminor = re.match(MAJMINREV[1], versionStr).groups()
    elif re.match(NOVERNOTAG[0], versionStr):#'0.0.0-20141229113116-0099840c98ae'
        major, minor, subminor, tagdate = re.match(NOVERNOTAG[1], versionStr).groups()
    elif re.match(VERTAG[0], versionStr):    #'1.6.3-0.20210406033725-bfc8ca285eb4'
        major, minor, subminor, taglevel, tagdate = re.match(VERTAG[1], versionStr).groups()
    else:
        print('Cannot extract date format from {}'.format(versionStr))
    numVersion = (int(major) * 1000000000 + int(minor) * 1000000 + int(subminor) * 1000 + int(taglevel)) * 100000000000000 + int(tagdate)
    return numVersion
	
def isVulnerableVersion(packageVersion, startVulnVer, endVulnVer):
    packVerNum = getVersionAsNumber(packageVersion)
    startVulnVerNum = getVersionAsNumber(startVulnVer)
    endVulnVerNum = getVersionAsNumber(endVulnVer)
    return packVerNum in range(startVulnVerNum, endVulnVerNum+1) or endVulnVerNum == 0

def doOutput(verVuls):
    for key in verVuls:
        vuln = verVuls[key]
        print('#' * 50)
        print('Package: {}  \tVersion: {}'.format(vuln[0], vuln[1]))
        print('{}'.format(vuln[2]))
        print('Module Path: \n{}'.format('\n'.join(vuln[3])))
		
if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: {} path_to_go_mod'.format(sys.argv[1]))
    else:
        deps = loadPackages(sys.argv[1])
        vulns = getVulns()
        actuals = {}
        for dep in deps:
            for d in deps[dep]:
                package, version = d.split('@')
                if package in vulns:
                    for vver in vulns[package]:
                        vulnerable = isVulnerableVersion(version, vver[1], vver[2])
                        if vulnerable:
                            vMsg = 'Vulnerable {} at version {} to {} ({} to {})'.format(package, version, vver[0], vver[1], 'No Fix' if vver[2] == '(unknown)' else vver[2])
                            whymod = getModWhy(sys.argv[1], package, version, deps)
                            key = (package, version, vver[0])
                            val = [package, version, vMsg, whymod]
                            if key in actuals:
                                if actuals[key] != val:
                                    print('already exists {} old {} new {} matches {}'.format(key, actuals[key], val, actuals[key] == val))
                            actuals[key] = val
                        else:
                            pass
        doOutput(actuals)
