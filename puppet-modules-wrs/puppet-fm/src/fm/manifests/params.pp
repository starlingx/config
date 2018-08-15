class fm::params {

  case $::osfamily {
    'RedHat': {
      $client_package = 'python-fmclient'
      $api_package    = 'fm-rest-api'
      $api_service    = 'fm-api'
    }
    'Debian': {
      $client_package = 'python-fmclient'
      $api_package    = 'fm-rest-api'
      $api_service    = 'fm-api'
    }
    default: {
      fail("Unsupported osfamily: ${::osfamily} operatingsystem")
    }

  } # Case $::osfamily

}
