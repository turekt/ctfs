# CMU Bomb lab

This lab is created by CMU and the objective of the lab is to defuse the bomb. The bomb has 6 phases and one secret phase which need to be reverse engineered or debugged in order to successfully defuse. Every phase is contained in its own function thus making reverse engineering easier since we need to focus on a specific function for each phase.

File with main function is provided with the binary and after command line arguments are parsed, the first phase is initiated. The bomb can be defused by providing a file path containing inputs or, if no file path is provided, the input is taken from stdin.

