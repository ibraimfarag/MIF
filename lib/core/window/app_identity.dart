/// The name this app presents to Windows and to the user.
///
/// One constant on purpose: the title `window_manager` sets, the tray tooltip and
/// the string [applyRoundedCorners] passes to `FindWindowW` must be identical, or
/// the lookup silently finds no window and the rounded corners stop being applied.
/// The executable's own FileDescription (`windows/runner/Runner.rc`) is the same
/// name, and that is what Task Manager shows in its Processes tab.
const String appDisplayName = 'MIF';
