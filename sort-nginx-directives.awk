# -------------------------------------------------------------------------------------------------
# sort-nginx-directives.awk -- Sort nginx directives by their contexts.
#
#  Descriptions
#  - Input
#    - nginx configuration file
#      sample.conf --------------------------------------------------------------------------------
#      user nginx;
#      pid /var/run/nginx.pid;
#
#      events {
#        worker_connections 1024;
#      }
#
#      http {
#        log_format  main  '$remote_addr \' - \n $remote_user [$time_local] "$request" ';
#        access_log  /var/log/nginx/access.log  main;
#        keepalive_timeout  65;
#        # proxy_redirect off;
#
#        server {
#          listen 80;
#          location / {
#            if ($request_method = POST) {
#              return 405;
#            }
#            proxy_pass http://example.com;
#          }
#        }
#      }
#      include /etc/nginx/conf.d/*.conf;
#      --------------------------------------------------------------------------------------------
#
#  - Output
#    - colon delimited format
#      Context Declared Order: Context Depth: Directives
#
#    - Example:
#      --------------------------------------------------------------------------------------------
#      $ awk -f sort-nginx-directives.awk sample.conf | sort -t: -k 1,1n
#      0:"main": user nginx; pid /var/run/nginx.pid; include /etc/nginx/conf.d/*.conf;
#      1:"main" "events": worker_connections 1024;
#      2:"main" "http": log_format  main  '$remote_addr \' - \n $remote_user [$time_local] "$request" '; access_log  /var/log/nginx/access.log  main; keepalive_timeout  65;
#      3:"main" "http" "server": listen 80;
#      4:"main" "http" "server" "location /": proxy_pass http://example.com;
#      5:"main" "http" "server" "location /" "if ($request_method = POST)": return 405;
#      --------------------------------------------------------------------------------------------
#
#  - Supported AWK Language
#    - gawk
#    - nawk
#    - mawk
#    - busybox
#
#  - Options
#    - find_path_opt_include=on (default off)
#      - When this option is "on", this program emulate the include directive with
#        "find -type f -path 'include directive value'" command.
#        In the above example, when 'include /etc/nginx/conf.d/*.conf;' matchs a file which
#        contains "deny 10.0.0.0/24;", output will be follwing example.
#        - Example:
#        ------------------------------------------------------------------------------------------
#        $ awk -f sort-nginx-directives.awk sample.conf | sort -t: -k 1,1n
#        0:"main": user nginx; pid /var/run/nginx.pid; include /etc/nginx/conf.d/*.conf; deny 10.0.0.0/24;
#        ...
#        ------------------------------------------------------------------------------------------
#
#  - Usage
#    - Audit that see if all server context has proxy_ssl_trusted_certificate directive.
#      - awk -f sort-nginx-directives.awk nginx.conf
#         | sed -n '/"server":/p'
#         | grep -v 'proxy_ssl_trusted_certificate'
#
# Version: 1.1.0
# Author: yuxki
# Repository: https://github.com/yuxki/sort-nginx-directives-awk
# Last Change: 2022/8/23
# License:
# MIT License
#
# Copyright (c) 2022 Yuxki
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# -------------------------------------------------------------------------------------------------

BEGIN {
  RS = "\f"
  FS = "\f"

  # not to use global variable, use associative array
  costructMidAr(midAr) # Mapping ID
}

{
  conf = $0

  # Check -----------------------------------------------------------------------------------------
  if (match(conf, getMatchReg(midAr))) {
    throwError(substr(conf, RSTART, RLENGTH) \
                  " in the configuration will cause unexpected behavior for this program.")
  }

  # Prepare Sorting -------------------------------------------------------------------------------
  conf = prepareSort(conf, str2MidMaps, midAr)
  gsub(/\n/, "", conf)

  # Do Sorting ------------------------------------------------------------------------------------
  sp = 0; rIdx = 1; coOrder = 1
  coStack[sp] = "\"main\""  # context opening stack
  diStack[sp] = ""          # directive statck
  orStack[sp] = 0           # context declare order stack

  while (1)  {
    sub(/^( |\t)*/ , "", conf)

    if (match(conf, /^}/)) {
      results[rIdx++] = orStack[sp] ":" coStack[sp] ":" diStack[sp]
      diStack[sp] = ""
      sp -= 1
      conf = substr(conf, RSTART + RLENGTH)
      continue
    }

    if (match(conf, /^[^\\\{;]*(\\.[^\\\{;]*)*\{/)) {
      coStr = substr(conf, RSTART, RLENGTH - 1)
      sub(/ *$/, "", coStr)
      sp += 1
      coStack[sp] = coStack[sp - 1] " \"" coStr "\""
      orStack[sp] = coOrder++
      conf = substr(conf, RSTART + RLENGTH)
      continue
    }

    if (match(conf, /^[^;]+;/)) {
      diStr = substr(conf, RSTART, RLENGTH)
      diStack[sp] = diStack[sp] " " diStr
      conf = substr(conf, RSTART + RLENGTH)

      if (find_path_opt_include == "on" && match(diStr, /^include( |\t)+/)) {
        file = substr(diStr, RSTART + RLENGTH)
        sub(/( |\t)*;$/, "", file)
        inConf = includeByFindPathOpt(file, midAr, str2MidMaps)
        inConf = prepareSort(inConf, str2MidMaps, midAr)
        gsub(/\n/, "", inConf)
        conf = inConf " " conf
      }
      continue
    }

    break
  }
  results[0] = orStack[sp] ":" coStack[sp] ":" diStack[sp]
}

# Print Results -----------------------------------------------------------------------------------
END {
  for (i in results){
    r = remapMid2Str(results[i], midAr, str2MidMaps)
    gsub(/\n/, "\\n", r)
    if (match(r,  getMatchReg(midAr))) {
      throwError("Unreplaced mapping id remains in " r)
    }
    print r
  }
}

# Functions ---------------------------------------------------------------------------------------
function throwError(ERROR_MSG) {
  print "[ERROR] sort-nginx-directives.awk: " ERROR_MSG | "cat 1>&2"
  exit 1
}

function mapStr2Mid(STR_MID_MAPS, STR, MID,
                    i) {
  for (i in STR_MID_MAPS) {
    if (i == MID)
      return 1
  }

  STR_MID_MAPS[MID] = STR
  return 0
}

function coverBySq(STR) {
  return "'" STR "'"
}

function isSQuoted(STR) {
  return match(STR, /^'[^\\']*(\\.[^\\']*)*'$/)
}

# Functions:Mapping ID Associative Array ----------------------------------------------------------
function costructMidAr(MID_AR){
  MID_AR["cuMid"] = 0
  MID_AR["bSlashsMid"] = -1

  # to protect original text in the config that equals the mapping id, put prefix to mapping id
  MID_AR["prefix"] = "sort-nginx-directives@"
  MID_AR["suffix"] = "-9c33b361a14a5021586ff16f1b34bcdc84f1b344d88502a943fc1762fb76c1f6"
  MID_AR["matchReg"] = MID_AR["prefix"] "[0-9]*" MID_AR["suffix"]
}

function getMid(MID_AR){
  return MID_AR["cuMid"]
}

function incMid(MID_AR){
  MID_AR["cuMid"] += 1
  return MID_AR["cuMid"]
}

function setBsMid(MID_AR, MID){
  MID_AR["bSlashsMid"] = MID
}

function getBsMid(MID_AR, MID){
  return MID_AR["bSlashsMid"]
}

function getMatchReg(MID_AR) {
  return MID_AR["prefix"] "[0-9]*" MID_AR["suffix"]
}

function safeMid(MID_AR, MID){
  return MID_AR["prefix"] MID MID_AR["suffix"]
}

function remapMid2Str(STR, MID_AR, STR_MID_MAPS,
                  str, mid) {
  str = STR

  for (mid in STR_MID_MAPS){
    # not remap mapping id first, because the it can be in the other mapped string
    if (mid == getBsMid(MID_AR))
      continue
    if (match(str, getMatchReg(MID_AR))) {
      gsub(safeMid(MID_AR, mid), STR_MID_MAPS[mid], str)
    }
  }

  if(getBsMid(MID_AR) >= 0) {
    if (match(str, getMatchReg(MID_AR)))
      gsub(safeMid(MID_AR, getBsMid(MID_AR)), STR_MID_MAPS[getBsMid(MID_AR)], str)
  }

  return str
}

# Functions:Sorting -------------------------------------------------------------------------------
function prepareSort(CONF, STR_MID_MAPS, MID_AR,
                     conf,
                     bSlashsMid,
                     typeCm, typeSq, typeDq,
                     noCmFlag, noSqFlag, noDqFlag,
                     cuType, cmRs, sqRs, dqRs, minRs) {

  # -----------------------------------
  # N   Type              Sufix/Prefix
  # -----------------------------------
  # 0   None              -
  # 1   Comment           cm
  # 2   Single Quote      sq
  # 3   Double Quote      dq
  # ------------------------------------
  typeCm = 1; typeSq = 2; typeDq = 3

  conf = CONF

  # map "\\" to the mapping id
  if (match(conf ,/\\\\/)) {
    setBsMid(MID_AR ,incMid(MID_AR))

    # to equalize each awks behaviors about "\\\\" as replacing text, map "\\" literal to
    # 2 same mapping id, and remap the every mapping id with "\" literal
    if(mapStr2Mid(STR_MID_MAPS, "\\", getBsMid(MID_AR)))
      throwError("Mapping ID:" getBsMid(MID_AR) " is already used.")
    gsub(/\\\\/,
         safeMid(MID_AR, getBsMid(MID_AR)) safeMid(MID_AR, getBsMid(MID_AR)),
         conf)
  }

  noCmFlag = 0; noSqFlag = 0; noDqFlag = 0;
  do {
    cuType = 0
    cmRs = 0; sqRs = 0; dqRs = 0; minRs = 0

    if (! noCmFlag && match(conf, /#/)) {
      cmRs = RSTART
      minRs = cmRs
      cuType = typeCm
    }
    else
      noCmFlag = 1

    if (! noSqFlag && match(conf, /[^\\]'/)) {
      sqRs = RSTART
      if (! minRs || RSTART < minRs) {
        minRs = sqRs
        cuType = typeSq
      }
    }
    else
      noSqFlag = 1

    if (! noDqFlag && match(conf, /[^\\]"/)) {
      dqRs = RSTART
      if (! minRs || RSTART < minRs) {
        minRs = dqRs
        cuType = typeDq
      }
    }
    else
      noDqFlag = 1

    if (cuType == typeCm) {
      sub(/#[^\n]*/, "", conf)
    }
    else if (cuType == typeSq) {
      if (match(conf, /[^\\]'[^\\']*(\\.[^\\']*)*'/)) {
        if(mapStr2Mid(STR_MID_MAPS, substr(conf, RSTART + 1, RLENGTH - 1), incMid(MID_AR)))
          throwError("Mapping ID:" getMid(MID_AR) " is already used.")

        sub(/[^\\]'[^\\']*(\\.[^\\']*)*'/,
            substr(conf, RSTART, 1) safeMid(MID_AR, getMid(MID_AR)),
            conf)
      }
      else {
        throwError("Single quotation is not closed.")
      }
    }
    else if (cuType == typeDq) {
      if (match(conf, /[^\\]"[^\\"]*(\\.[^\\"]*)*"/)) {
        if(mapStr2Mid(STR_MID_MAPS, substr(conf, RSTART + 1, RLENGTH - 1), incMid(MID_AR)))
          throwError("Mapping ID:" getMid(MID_AR) " is already used.")

        sub(/[^\\]"[^\\"]*(\\.[^\\"]*)*"/,
            substr(conf, RSTART, 1) safeMid(MID_AR, getMid(MID_AR)),
            conf)
      }
      else {
        throwError("Double quotation is not closed.")
      }
    }
  } while (cuType != 0)

  return conf
}

function includeByFindPathOpt(INCLUDE_VALUE, MID_AR, STR_MID_MAPS,
                              path, findCmd, files, filesStr, inConf,
                              i) {
  path = INCLUDE_VALUE

  if (match(path, /( |\t)/))
    throwError("Found the include direcive which has more than one arguments.")

  if (match(path, /^( |\t)*$/))
    throwError("Found the include direcive which has no argument.")

  path = remapMid2Str(path, MID_AR, STR_MID_MAPS)

  if (match(path, /'[^\\']*(\\.[^\\']*)*'/))
    path = substr(path, RSTART + 1, RLENGTH - 2)

  if (match(path, /"[^\\"]*(\\.[^\\"]*)*"/))
    path = substr(path, RSTART + 1, RLENGTH - 2)

  path = coverBySq(path)
  if (! isSQuoted(path))
    throwError("find -path option value " path " is not quoted by single quote.")

  findCmd = "find -type f -path " path
  if (system(findCmd " > /dev/null"))
    throwError(findCmd " command failed.")

  findCmd | getline filesStr
  close(findCmd)

  sub(/\n$/, "", filesStr)
  if (filesStr == "")
    throwError(path ": Not found.")

  split(filesStr, files, "\n")

  for (file in files) {
     getline < files[file]
     inConf = inConf $0
     close(file)
  }

  return inConf
}
