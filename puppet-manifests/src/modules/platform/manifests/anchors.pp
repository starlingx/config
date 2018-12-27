class platform::anchors {
  anchor { 'platform::networking': }
  -> anchor { 'platform::services': }
}
