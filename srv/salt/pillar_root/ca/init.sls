x509-ca:
  output: /example/output/location
  defaults:
    C: AU
    ST: Queensland
    L: Brisbane
    O: Some Org
    OU: ICT
    Email: security@some.org
  root:
    equate_root_ca:
      CN: "Some Org Root CA"
      sub:
        equate_a1_ca:
          CN: "Some Org A1 CA"
          sub:
            equate_user_ca:
              CN: "Some Org A1 User CA"
              create:
                test_user:
                  CN: "Test User"
            equate_server_ca:
              CN: "Some Org A1 Server CA"
              create:
                test_server:
                  CN: "Test Server"
                  extendedKeyUsage: serverAuth, clientAuth
                  subjectAltName: DNS:localhost.localdomain IP:127.0.0.1
                  nsComment: blah
                  nsCertType: server
                  days_valid: 10000
                  version: 10
                  serial_bits: 128
                  algorithm: sha512
                  backup: True
            equate_device_ca:
              CN: "Some Org A1 Device CA"
              create:
                test_device:
                  CN: "Test Device"
              revoked:
                dead_device:
                  serial_number: D6:D2:DC:D8:4D:5C:C0:F4
                  not_after: "\"2016-01-01 00:00:00\""
                  revocation_date: "\"2015-02-25 00:00:00\""
                  reason: cessationOfOperation
