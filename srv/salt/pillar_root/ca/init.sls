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
    org_root_ca:
      CN: "Some Org Root CA"
      crlDistributionPoints: URI:http://some.org/crl/root.crl
      sub:
        org_a1_ca:
          CN: "Some Org A1 CA"
          crlDistributionPoints: URI:http://some.org/crl/a1.crl
          sub:
            org_user_ca:
              CN: "Some Org A1 User CA"
              crlDistributionPoints: URI:http://some.org/crl/a1_user.crl
              create:
                test_user1:
                  CN: "Monkey Magic"
                  GN: "Monkey"
                  SN: "Magic"
                  extendedKeyUsage: clientAuth
                  nsCertType: client
                  days_valid: 10000
                test_user2:
                  CN: "Trippi Tarka"
                  GN: "Trippi"
                  SN: "Tarka"
                  extendedKeyUsage: clientAuth
                  nsCertType: client
                  days_valid: 10000
            org_server_ca:
              CN: "Some Org A1 Server CA"
              crlDistributionPoints: URI:http://some.org/crl/a1_server.crl
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
            org_device_ca:
              CN: "Some Org A1 Device CA"
              crlDistributionPoints: URI:http://some.org/crl/a1_device.crl
              create:
                test_device:
                  CN: "Test Device"
              revoked:
                dead_device:
                  serial_number: D6:D2:DC:D8:4D:5C:C0:F4
                  not_after: "\"2025-01-01 00:00:00\""
                  revocation_date: "\"2015-02-25 00:00:00\""
                  reason: cessationOfOperation
