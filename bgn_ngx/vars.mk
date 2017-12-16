%:
	@echo '$*=[$($*)]'
 
d-%:
	@echo '$*=[$($*)]'
	@echo '  origin = $(origin $*)'
	@echo '   value = $(value  $*)'
	@echo '  flavor = $(flavor $*)'
