# Logging Metrics

As your number of clients grows, there will be a natural tendency for them to drift, using different clients.  It's hard to go and police desktops on a remote workforce, so this seeks to capture some of the client information as your users come and go.

This is information not readily available in the status log, or, minimally, it is possible to miss thingss if you survey the log instead of capturing via hooks.

# Variables
[OpenVPN](https://community.openvpn.net/openvpn/wiki/Openvpn24ManPage#lbAV) sends your hooks a lot of information, but it's thrown away after the script exits.  We're going to capture some of it.

## Too Much Information
The obvious first approach would be to capture absolutely every variable that is passed in.  This is actually how the research began:

    for varname in os.environ:
      print varname, ':', os.environ['varname']

This gave me the list to start from.  Redacted / sanitized / sorted:

    IV_COMP_STUB : 1
    IV_COMP_STUBv2 : 1
    IV_GUI_VER : Viscosity_1.8.2b1_1512
    IV_HWADDR : 70:56:81:aa:77:07
    IV_LZ4 : 1
    IV_LZ4v2 : 1
    IV_LZO : 1
    IV_NCP : 2
    IV_PLAT : mac
    IV_PROTO : 2
    IV_SSL : OpenSSL_1.1.1d__10_Sep_2019
    IV_TCPNL : 1
    IV_VER : 2.4.8
    X509_0_C : US
    X509_0_CN : me@work.net
    X509_0_L : Corvallis
    X509_0_O : Work
    X509_0_ST : Oregon
    X509_0_emailAddress : me@work.net
    X509_1_C : US
    X509_1_CN : Work - ClearPass Onboard CA (Signing)
    X509_1_L : Corvallis
    X509_1_O : Work Company
    X509_1_OU : IT - NetOps
    X509_1_ST : Oregon
    X509_1_emailAddress : ca-admin@work.net
    X509_2_C : US
    X509_2_CN : Work - ClearPass Onboard CA
    X509_2_L : Corvallis
    X509_2_O : Work Company
    X509_2_OU : IT - NetOps
    X509_2_ST : Oregon
    X509_2_emailAddress : ca-admin@work.net
    auth_control_file : /tmp/openvpn_acf_47f159f6897c3e75727158b4557f7283.tmp
    bytes_received : 39700
    bytes_sent : 41161
    common_name : me@work.net
    config : udp-stage.conf
    daemon : 0
    daemon_log_redirect : 1
    daemon_pid : 1022
    daemon_start_time : 1572267794
    dev : tun0
    dev_type : tun
    ifconfig_broadcast : 10.58.239.255
    ifconfig_local : 10.58.238.1
    ifconfig_netmask : 255.255.254.0
    ifconfig_pool_netmask : 255.255.254.0
    ifconfig_pool_remote_ip : 10.58.238.2
    link_mtu : 1621
    local_port_1 : 1194
    proto_1 : udp
    redirect_gateway : 0
    remote_port_1 : 1194
    script_context : init
    script_type : client-disconnect
    time_ascii : Thu Nov  7 17:27:04 2019
    time_duration : 600
    time_unix : 1573147624
    tls_digest_0 : c8:cc:b3:5c:58:4f:8c:1a:3f:3a:91:3b:b2:a3:39:9f:40:93:d9:ff
    tls_digest_1 : b0:fb:cc:5b:ce:0a:48:96:eb:3a:47:45:3e:52:e3:b4:7b:4a:8e:09
    tls_digest_2 : 2a:e5:ff:d8:ba:1f:90:c8:3c:fa:09:2b:50:19:47:12:1a:5c:22:a4
    tls_digest_sha256_0 : b9:a2:b5:83:2c:de:95:ca:f5:10:ba:24:36:2d:26:b5:d4:98:34:d4:de:0c:79:8c:ee:4d:49:51:28:2e:88:1b
    tls_digest_sha256_1 : 92:e5:2e:76:6f:a4:4d:9f:ce:47:37:a7:f1:9f:cb:58:af:67:8e:2a:dc:ca:69:d6:be:97:4d:40:a5:c0:45:c7
    tls_digest_sha256_2 : fd:81:bd:a3:c5:36:26:22:df:f0:cb:90:42:76:27:ae:99:fa:a3:8c:6e:29:9d:08:16:c0:2d:57:02:6d:ca:01
    tls_id_0 : C=US, ST=Oregon, L=Corvallis, O=Work, CN=me@work.net, emailAddress=me@work.net
    tls_id_1 : C=US, ST=Oregon, L=Corvallis, O=Work Company, OU=IT - NetOps, CN=Work - ClearPass Onboard CA (Signing), emailAddress=ca-admin@work.net
    tls_id_2 : C=US, ST=Oregon, L=Corvallis, O=Work Company, OU=IT - NetOps, CN=Work - ClearPass Onboard CA, emailAddress=ca-admin@work.net
    tls_serial_0 : 1199
    tls_serial_1 : 488
    tls_serial_2 : 487
    tls_serial_hex_0 : 04:af
    tls_serial_hex_1 : 01:e8
    tls_serial_hex_2 : 01:e7
    trusted_ip : 63.245.220.198
    trusted_port : 65460
    tun_mtu : 1500
    untrusted_ip : 63.245.220.198
    untrusted_port : 65460
    username : me@work.net
    verb : 4

This was a lot to go over, but first, let's break down the design goals.

- Don't capture anything that will come back to haunt us if it leaks.
- Don't capture server-related data.
- Capture enough to do known user client research:
  - Find clients that need upgrading
  - Find clients that are outliers in total usage
- Capture enough to enable future research for questions we may not have thought of.
- Since I'm writing public code, think about more than my own use case

## Start whittling

Looking at the design requirements, what I came up with is that, in code, I should prohibit exporting server-related items.
`config`, `daemon`, `daemon_log_redirect`, `daemon_pid`, `daemon_start_time`, `script_context`, `verb`, and `auth_control_file` leak information about the server instance that should not have any impact upon the client that is connecting, so they are hard-coded as "not allowed".

Further, `password` is removed, as it could be passed in `via-env`, and we don't want to let that be captured and exported.

Looking over what's left, I see a lot of variables I don't need.  For example, `X509_{n}_{field_name}` are just breakouts of `tls_id_{n}`, and since this is a logger more than a decider, I don't need the breakout.  But someone else might.  So I believe the best course here is, having prohibited the export of sensitive variables, to let any of the rest be exported if desired.  And that means letting it be a runtime configuration.

## Start building

The config file requires a directory parameter, `metrics-log-dir`.  If that exists, is a directory, and is writable, we log a json of the variables you request.

Which variables? `metrics` in the config file should be an array (set) of strings listing variables you wish to capture.  We force common_name and time_unix to appear because they are needed for the spool directory naming convention.

`openvpn-client-disconnect.conf.example` has an example with a good setup.

What you choose to do with the spooled json afterwards is up to you, hence we don't do much with the values in the JSON.  They are passed along as they are found in openvpn, meaning they come out as strings (e.g `link_mtu` is "1500" (a string) and not 1500 (an int)).  This is so there's little surprise, and your code is closer to being "just how it would be if it were hooked into openvpn."
