This alarm code correctly detects errors in log files. 
The active packet logger should work based off of the attack definitions but
is untested against the attacks.

This work was done without collaboration. 

This assignmnet took approximately 10 hours.

Are the heuristics used in this assignment to determine incidents "even that good"?
	While the methods used in this assignment detect some attacks they by no means
	are fully inclusive. One example is the nmap scan detection which merely examins
	the user agent. If an attack so chose to change the user agent it would go undetected.

If you have spare time in the future, what would you add to the program or do differently with regards to detecting incidents?
	The first thing I would do is test the active logger by making a program to make packets
	with customized values and send them on the local card. Then I would attempt to make a
	more comprehensive scan detection heuristic that would log the average time between connections
	with the same IP and flag any that re-occur with consistant timing within a threshold.
	