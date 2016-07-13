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
            equate_device_ca:
              CN: "Some Org A1 Device CA"
              create:
                test_device:
                  CN: "Test Device"


