package sast

repos := {"repo1", "repo2", "repo3", "devops"}

deny[msg] {
  some i
  contains(data.conftest.file.name, repos[i])
  input.metrics._totals["SEVERITY.MEDIUM"] > 0
  msg := sprintf("SAST Test failed: %d medium severitie(s)", [input.metrics._totals["SEVERITY.MEDIUM"]])
}

deny[msg] {
  input.metrics._totals["SEVERITY.HIGH"] > 0
  msg := sprintf("SAST Test failed: %d high severitie(s)", [input.metrics._totals["SEVERITY.HIGH"]])
}
