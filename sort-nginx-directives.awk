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
#        include /etc/nginx/conf.d/*.conf;
#      }
#      --------------------------------------------------------------------------------------------
#
#  - Output
#    - colon delimited format
#      Context Declared Order: Context Depth: Directives
#
#    - Example:
#      --------------------------------------------------------------------------------------------
#      $ awk -f sort-nginx-directives.awk sample.conf | sort
#      0:"main": user nginx; pid /var/run/nginx.pid;
#      1:"main" "events": worker_connections 1024;
#      2:"main" "http": log_format  main  '$remote_addr \' - \n $remote_user [$time_local] "$request" '; access_log  /var/log/nginx/access.log  main; keepalive_timeout  65; include /etc/nginx/conf.d/*.conf;
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
#  - Usage
#    - Audit that see if all server context has proxy_ssl_trusted_certificate directive.
#      - awk -f sort-nginx-directives.awk nginx.conf
#         | sed -n '/"server":/p'
#         | grep -v 'proxy_ssl_trusted_certificate'
#
# Version: 1.0.1
# Author: yuxki
# Repository: https://github.com/yuxki/sort-nginx-directives-awk
# Last Change: 2022/8/22
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

  # -----------------------------------
  # N   Type              Sufix/Prefix
  # -----------------------------------
  # 0   None              -
  # 1   Comment           cm
  # 2   Single Quote      sq
  # 3   Double Quote      dq
  # 4   Directive         di
  # 5   Context Opening   co
  # 6   Context Closing   cc
  # ------------------------------------
  typeCm = 1; typeSq = 2; typeDq = 3; typeDi = 4;

  mid = 0 # Mapping ID
  # to protect original text in the config that equals the mapping id, put prefix to mapping id
  midPrefix = "sort-nginx-directives@"
  midSuffix = "-9c33b361a14a5021586ff16f1b34bcdc84f1b344d88502a943fc1762fb76c1f6"
  midMatchReg = midPrefix "[0-9]*" midSuffix
}

{
  conf = $0

  # Check -----------------------------------------------------------------------------------------
  if (match(conf, midMatchReg)) {
    throwError(substr(conf, RSTART, RLENGTH) " in the configuration will cause unexpected behavior for this program.")
  }

  # Prepare Sorting -------------------------------------------------------------------------------
  # map "\\" to the mapping id
  if (match(conf ,/\\\\/)) {
    mid +=1
    bSlashsMid = mid

    # to equalize each awks behaviors about "\\\\" as replacing text, map "\\" literal to
    # 2 safeMid(bSlashsMid), and remap every safeMid(bSlashsMid) with "\" literal
    if(mapStr2Mid(str2MidMaps, "\\", bSlashsMid))
      throwError("Mapping ID:" bSlashsMid " is already used.")
    gsub(/\\\\/, safeMid(bSlashsMid) safeMid(bSlashsMid), conf)
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
        mid +=1
        if(mapStr2Mid(str2MidMaps, substr(conf, RSTART + 1, RLENGTH - 1), mid))
          throwError("Mapping ID:" mid " is already used.")

        sub(/[^\\]'[^\\']*(\\.[^\\']*)*'/, substr(conf, RSTART, 1) safeMid(mid), conf)
      }
      else {
        throwError("Single quotation is not closed.")
      }
    }
    else if (cuType == typeDq) {
      if (match(conf, /[^\\]"[^\\"]*(\\.[^\\"]*)*"/)) {
        mid +=1
        if(mapStr2Mid(str2MidMaps, substr(conf, RSTART + 1, RLENGTH - 1), mid))
          throwError("Mapping ID " mid " is already used.")

        sub(/[^\\]"[^\\"]*(\\.[^\\"]*)*"/, substr(conf, RSTART, 1) safeMid(mid), conf)
      }
      else {
        throwError("Double quotation is not closed.")
      }
    }
  } while (cuType != 0)

  gsub(/\n/, "", conf)

  # Do Sorting ------------------------------------------------------------------------------------
  sp = 0; rIdx = 1; coOrder = 1
  coStack[sp] = "\"main\""
  diStack[sp] = ""
  orStack[sp] = 0

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
      diStack[sp] = diStack[sp] " " substr(conf, RSTART, RLENGTH)
      conf = substr(conf, RSTART + RLENGTH)
      continue
    }

    break
  }
  results[0] = orStack[sp] ":" coStack[sp] ":" diStack[sp]
}

# Print Results -----------------------------------------------------------------------------------
END {
  for (i in results){
    r = remapMid2Str(results[i], str2MidMaps)
    gsub(/\n/, "\\n", r)
    if (match(r, midMatchReg)) {
      throwError("Unreplaced mapping id remains in " r)
    }
    print r
  }
}

# Functions ---------------------------------------------------------------------------------------
function safeId(SAFE_PREFIX, ID, SAFE_SUFFIX) {
  return SAFE_PREFIX ID SAFE_SUFFIX
}

function safeMid(MID){
  return safeId(midPrefix, MID, midSuffix)
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

function remapMid2Str(STR, STR_MID_MAPS,
                  str, mid) {
  str = STR

  for (mid in STR_MID_MAPS){
    # not remap mapping id first, because the it can be in the other mapped string
    if (mid == bSlashsMid)
      continue
    if (match(str, midMatchReg)) {
      gsub(safeMid(mid), STR_MID_MAPS[mid], str)
    }
  }

  if(bSlashsMid) {
    if (match(str, midMatchReg))
      gsub(safeMid(bSlashsMid), STR_MID_MAPS[bSlashsMid], str)
  }

  return str
}

function throwError(ERROR_MSG) {
  print "[ERROR] sort-nginx-directives.awk: " ERROR_MSG | "cat 1>&2"
  exit 1
}
