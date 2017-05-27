pipeline {
  agent any
  options {
    ansiColor('xterm')
    timestamps()
    timeout(time: 1, unit: 'HOURS')
  }

  environment {
    http_proxy = "http://proxy.int.govcert.etat.lu:8080"
    https_proxy = "http://proxy.int.govcert.etat.lu:8080"
  }

  stages {
    stage('Lint - py34') {
      steps {
        sh "tox -e py34"
      }
    }

   stage('Analysis - pylint') {
      steps {
        script { analyze_pylint() }
      }
    }

   stage('Analysis - pyflakes') {
      steps {
        script { analyze_pyflakes() }
      }
    }
  }
}


def analyze_pylint() {
      step([$class: 'WarningsPublisher', canComputeNew: false, canResolveRelativePaths: false, defaultEncoding: '', excludePattern: '', healthy: '', includePattern: '', messagesPattern: '', parserConfigurations: [[parserName: 'PyLint', pattern: 'pylint.log']], unHealthy: ''])
}


def analyze_pyflakes() {
      step([$class: 'WarningsPublisher', canComputeNew: false, canResolveRelativePaths: false, defaultEncoding: '', excludePattern: '', healthy: '', includePattern: '', messagesPattern: '', parserConfigurations: [[parserName: 'PyFlakes', pattern: 'pyflakes.log']], unHealthy: ''])
}
