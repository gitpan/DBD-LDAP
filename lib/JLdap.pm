#!/usr/local/bin/perl5

package JLdap;

require 5.002;

use Net::LDAP::Entry;
use vars qw($VERSION);

#use Fcntl; 

##++
##  Global Variables. Declare lock constants manually, instead of 
##  importing them from Fcntl.
##
use vars qw ($VERSION);
##--

$JLdap::VERSION = '0.05';

#my $NUMERICTYPES = '^(NUMBER|FLOAT|DOUBLE|INT|INTEGER|NUM)$';       #20000224
#my $STRINGTYPES = '^(VARCHAR2|CHAR|VARCHAR|DATE|LONG|BLOB|MEMO)$';

##++
##  Public Methods and Constructor
##--

sub new
{
    my $class = shift;
    my $self;

    $self = {
                commands     => 'select|update|delete|alter|insert|create|drop',
                column       => '[A-Za-z0-9\~\x80-\xFF][\w\x80-\xFF]+',
		_select      => '[\w\x80-\xFF\*,\s\~]+',
		path         => '[\w\x80-\xFF\-\/\.\:\~\\\\]+',
		table        => '',
		timestamp    => 0,
		fields       => {},
		use_fields   => '',
		key_fields   => '',
		order        => [],
		types        => {},
		lengths      => {},
		scales       => {},
		defaults     => {},
		records      => [],
		errors       => {},
		lasterror    => 0,     #JWT:  ADDED FOR ERROR-CONTROL
		lastmsg      => '',
		CaseTableNames  => 0,    #JWT:  19990991 TABLE-NAME CASE-SENSITIVITY?
		LongTruncOk  => 0,     #JWT: 19991104: ERROR OR NOT IF TRUNCATION.
		RaiseError   => 0,     #JWT: 20000114: ADDED DBI RAISEERROR HANDLING.
		silent       => 0,
		ldap_dbh			 => 0,
		ldap_sizelimit => 0,    #JWT: LIMIT #RECORDS FETCHED, IF SET.
		ldap_timelimit => 0,    #JWT: LIMIT #RECORDS FETCHED, IF SET.
		ldap_deref => 0,    #JWT: LIMIT #RECORDS FETCHED, IF SET.
		ldap_typesonly => 0,
		ldap_callback => 0,
		ldap_scope => 0,
		ldap_inseparator => '|',
		ldap_outseparator => '|',
		ldap_firstonly => 0,
		dirty			 => 0      #JWT: 20000229: PREVENT NEEDLESS RECOMMITS.
	    };

    bless $self, $class;

    $self->initialize;
    return $self;
}
sub initialize
{
	my $self = shift;

	$self->define_errors;
}

sub sql
{
	my ($self, $csr, $query) = @_;

	my ($command, $status, $base, $fields);
	return wantarray ? () : -514  unless ($query);
	$self->{lasterror} = 0;
	$self->{lastmsg} = '';
	$query   =~ s/\n/ /gs;
	$query   =~ s/^\s*(.*?)\s*$/$1/;
	$query = 'select tables'  if ($query =~ /^show\s+tables$/i);
	$query = 'select tables'  if ($query =~ /^select\s+TABLE_NAME\s+from\s+USER_TABLES$/i);  #ORACLE-COMPATABILITY.
	$command = '';

	if ($query =~ /^($self->{commands})/io)
	{
		$command = $1;
		$command =~ tr/A-Z/a-z/;    #ADDED 19991202!
		$status  = $self->$command ($csr, $query);
		if (ref ($status) eq 'ARRAY')   #SELECT RETURNED OK (LIST OF RECORDS).
		{
			return wantarray ? @$status : $status;
		}
		else
		{
			if ($status < 0)
			{             #SQL RETURNED AN ERROR!
				$self->display_error ($status);
				#return ($status);
				return wantarray ? () : $status;
			}
			else
			{                        #SQL RETURNED OK.
				return wantarray ? ($status) : $status;
			}
		}
	}
	else
	{
		return wantarray ? () : -514;
	}
}

sub select
{
	my ($self, $csr, $query) = @_;

	my (@ordercols) = ();
	$regex = $self->{_select};
	$path  = $self->{path};
	my (@rtnvals) = ();

	my $distinct;
	$distinct = 1  if ($query =~ s/select\s+distinct(\s+\w|\s*\(|\s+\*)/select $1/i);
	my ($dbh) = $csr->FETCH('ldap_dbh');
	my ($tablehash);

	if ($query =~ /^select tables$/i)
	{
		$tablehash = $dbh->FETCH('ldap_tablenames');
		$self->{use_fields} = 'TABLE_NAME';  #ADDED 20000224 FOR DBI!
		$values_or_error = [];
		for ($i=0;$i<=$#{$tablehash};$i++)
		{
			push (@$values_or_error,[$tablehash->[$i]]);
		}
		unshift (@$values_or_error, ($#{$tablehash}+1));
		return $values_or_error;
	}
	elsif ($query =~ /^select\s+                         # Keyword
			($regex)\s+                       # Columns
			from\s+                           # 'from'
			($path)(.*)$/iox)
	{           
		($attbs, $table, $extra) = ($1, $2, $3);

		$table =~ tr/A-Z/a-z/  unless ($self->{CaseTableNames});  #JWT:TABLE-NAMES ARE NOW CASE-INSENSITIVE!
		$self->{file} = $table;
		if ($extra =~ s/([\s|\)]+)order\s+by\s*(.*)/$1/i)
		{
			$orderclause = $2;
			@ordercols = split(/,/,$orderclause);
			$descorder = ($ordercols[$#ordercols] =~ s/(\w+\W+)desc(?:end|ending)?$/$1/i);  #MODIFIED 20000721 TO ALLOW "desc|descend|descending"!
			for $i (0..$#ordercols)
			{
				$ordercols[$i] =~ s/\s//g;
				$ordercols[$i] =~ s/[\(\)]+//g;
			}
		}
		$tablehash = $dbh->FETCH('ldap_tables');
		return (-524)  unless ($tablehash->{$table});

		my ($base, $objfilter, $dnattbs, $allattbs, $alwaysinsert) = split(/\:/,$tablehash->{$table});
		$attbs = $allattbs  if ($allattbs && $attbs =~ s/\*//);
		$attbs =~ s/\s//g;
		$attbs =~ tr/A-Z/a-z/;
		@{$self->{order}} = split(/,/, $attbs)  unless ($attbs eq '*');
		my $fieldnamehash = ();
		my $attbcnt = 0;
		foreach my $i (@{$self->{order}})
		{
			$fieldnamehash{$i} = $attbcnt++;
		}
		my ($ldap) = $csr->FETCH('ldap_ldap');
		$objfilter ||= 'objectclass=*';
		$objfilter = "($objfilter)"  unless ($objfilter =~ /^\(/);
		if ($extra =~ /^\s+where\s*(.+)$/i)
		{
			$filter = $self->parse_expression($1);
			$filter = '('.$filter.')'  unless ($filter =~ /^\(/);
			$filter = "(&$objfilter$filter)";
		}
		else
		{
			$filter = $objfilter;
		}
		my $data;
		my (@searchops) = (
				'base' => $base,
				'filter' => $filter,
				'attrs' => [split(/\,/, $attbs)]
		);
		foreach my $i (qw(ldap_sizelimit ldap_timelimit deref typesonly 
		callback))
		{
			$j = $i;
			$j =~ s/^ldap_//;
			push (@searchops, ($j, $self->{$i}))  if ($self->{$i});
		}
		push (@searchops, ('scope', ($self->{ldap_scope} || 'one')));
		$data = $ldap->search(@searchops) 
				or return($self->ldap_error($@,"Search failed to return object: filter=$filter (".$data->error().")"));

		my ($j) = 0;
		my (@varlist) = ();
		while (my $entry = $data->shift_entry())
		{
			$dn = $entry->dn();
			next  unless ($dn =~ /$base$/);
			@attributes = $entry->attributes;
			unless ($attbcnt)
			{
				$attbs = join(',',@attributes);
				$attbcnt = 0;
				@{$self->{order}} = @attributes;
				foreach my $i (@{$self->{order}})
				{
					$fieldnamehash{$i} = $attbcnt++;
				}
			}
			$varlist[$j] = [];
			for (my $i=0;$i<$attbcnt;$i++)
			{
				$varlist[$j][$i] = '';
			}
			$i = 0;
			foreach my $attr (@{$self->{order}})
			{
				$valuesref = $entry->get($attr);
				if ($self->{ldap_firstonly} && $self->{ldap_firstonly} <= scalar (@{$valuesref}))
				{
					#$varlist[$j][$fieldnamehash{$attr}] = join($self->{ldap_outseparator}, $valuesref->[0]); #CHGD. 20010829 TO NEXT.
					$varlist[$j][$fieldnamehash{$attr}] = join($self->{ldap_outseparator}, @{$valuesref}[0..($self->{ldap_firstonly}-1)]);
				}
				else
				{
					$varlist[$j][$fieldnamehash{$attr}] = join($self->{ldap_outseparator}, @$valuesref) || '';
				}
				unless ($valuesref[0])
				{
					$varlist[$j][$fieldnamehash{dn}] = $dn  if ($attr eq 'dn');
				}
				$i++;
			}
			++$j;
		}
		$self->{use_fields} = $attbs;
		if ($distinct)   #THIS MAKES "DISTINCT" WORK.
		{
			my (%disthash);
			for (my $i=0;$i<=$#varlist;$i++)
			{
				++$disthash{join("\x02",@{$varlist[$i]})};
			}
			@varlist = ();
			foreach my $i (keys(%disthash))
			{
				push (@varlist, [split(/\x02/, $i, -1)]);
			}
		}
		if ($#ordercols >= 0)   #SORT 'EM!
		{
			my @SV;
			for (my $i=0;$i<=$#varlist;$i++)
			{
				$SV[$i] = '';
				foreach my $j (@ordercols)
				{
					$SV[$i] .= $varlist[$i][$fieldnamehash{$j}] . "\x01";
				}
			}
			@sortvector = &sort_elements(\@SV);
			@sortvector = reverse(@sortvector)  if ($descorder);
			@SV = ();
			while (@sortvector)
			{
				push (@SV, $varlist[shift(@sortvector)]);
			}
			@varlist = @SV;
			@SV = ();
		}
		return [($#attributes+1), @varlist];
	}
	else     #INVALID SELECT STATEMENT!
	{
		return (-503);
	}
}

sub sort_elements
{
	my (@elements, $line, @sortlist, @sortedlist, $j, $t, $argcnt, $linedata, 
			$vectorid, @sortvector);

	my ($lo) = 0;
	my ($hi) = 0;
	$lo = shift  unless (ref($_[0]));
	$hi = shift  unless (ref($_[0]));

	if ($lo || $hi)
	{
		for ($j=0;$j<=$#{$_[0]};$j++)
		{
			$sortvector[$j] = $j;
		}
	}
	$hi ||= $#{$_[0]};
	$argcnt = scalar(@_);
	for (my $i=$lo;$i<=$hi;$i++)
	{
		$line = $_[0][$i];
		for ($j=1;$j<$argcnt;$j++)
		{
			$line .= "\x02" . $_[$j][$i];
		}
		$line .= "\x04".$i;
		push (@sortlist, $line);
	}

	@sortedlist = sort @sortlist;
	$i = $lo;
	foreach $line (@sortedlist)
	{
		($linedata,$vectorid) = split(/\x04/,$line);
		(@elements) = split(/\x02/,$linedata);
		$t = $#elements  unless $t;
		for ($j=$t;$j>=1;$j--)
		{
			#push (@{$_[$j]}, $elements[$j]);
			${$_[$j]}[$i] = $elements[$j];
		}
		$sortvector[$i] = $vectorid;
		$elements[0] =~ s/\s+//g;
		${$_[0]}[$i] = $elements[$j];
		++$i;
	}
	return @sortvector;
}

sub ldap_error
{
	my ($self,$errcode,$errmsg,$whichone) = @_;

	$err = $errcode || -1;
	$errdetails = $errmsg;
	$err = -1 * $err  if ($err > 0);
	return ($err)  unless ($warn);

	print "Content-type: text/html\nWindow-target: _parent", "\n\n"  
			if ($warn == 1);

	return ($self->display_error($errcode));
}

sub display_error
{	
	my ($self, $error) = @_;

	$other = $@ || $! || 'None';

	print STDERR <<Error_Message  unless ($self->{silent});

Oops! The following error occurred when processing your request:

    $self->{errors}->{$error} ($errdetails)

Here's some more information to help you:

	file:  $self->{file}
    $other

Error_Message

#JWT:  ADDED FOR ERROR-CONTROL.

	$self->{lasterror} = $error;
	$self->{lastmsg} = "$error:" . $self->{errors}->{$error};
	$self->{lastmsg} .= '('.$errdetails.')'  if ($errdetails);  #20000114

	$errdetails = '';   #20000114
	die $self->{lastmsg}  if ($self->{RaiseError});  #20000114.

    #return (1);
	return ($error);
}

sub commit
{
	my ($self) = @_;
	my ($status) = 1;
	my ($dbh) = $self->FETCH('ldap_dbh');
	my ($autocommit) = $dbh->FETCH('AutoCommit');

	$status = $dbh->commit()  unless ($autocommit);

	$self->{dirty} = 0  if ($status > 0);
	return undef  if ($status <= 0);   #ADDED 20000103
	return $status;
}

##++
##  Private Methods
##--

sub define_errors
{
	my $self = shift;
	my $errors;

	$errors = {};

	$errors->{'-501'} = 'Could not open specified database.';
	$errors->{'-502'} = 'Specified column(s) not found.';
	$errors->{'-503'} = 'Incorrect format in [select] statement.';
	$errors->{'-504'} = 'Incorrect format in [update] statement.';
	$errors->{'-505'} = 'Incorrect format in [delete] statement.';
	$errors->{'-506'} = 'Incorrect format in [add/drop column] statement.';
	$errors->{'-507'} = 'Incorrect format in [alter table] statement.';
	$errors->{'-508'} = 'Incorrect format in [insert] command.';
	$errors->{'-509'} = 'The no. of columns does not match no. of values.';
	$errors->{'-510'} = 'A severe error! Check your query carefully.';
	$errors->{'-511'} = 'Cannot write the database to output file.';
	$errors->{'-512'} = 'Unmatched quote in expression.';
	$errors->{'-513'} = 'Need to open the database first!';
	$errors->{'-514'} = 'Please specify a valid query.';
#    $errors->{'-515'} = 'Cannot get lock on database file.';
#    $errors->{'-516'} = 'Cannot delete temp. lock file.';
	$errors->{'-517'} = "Built-in function failed ($@).";
	$errors->{'-518'} = "Unique Key Constraint violated.";  #JWT.
	$errors->{'-519'} = "Field would have to be truncated.";  #JWT.
	$errors->{'-520'} = "Can not create existing table (drop first!).";  #20000225 JWT.
	$errors->{'-521'} = "Can not change datatype on non-empty table.";  #20000323 JWT.
	$errors->{'-522'} = "Can not decrease field-size on non-empty table.";  #20000323 JWT.
	$errors->{'-523'} = "Update Failed to commit changes.";  #20000323 JWT.
	$errors->{'-524'} = "No such table.";  #20000323 JWT.
	$errors->{'-599'} = 'General error.';

	$self->{errors} = $errors;

	return (1);
}

sub parse_expression
{
	my ($self, $s) = @_;

	$s =~ s/\s+$//;     #STRIP OFF LEADING AND TRAILING WHITESPACE.
	$s =~ s/^\s+//;
	return unless ($s);


	my $relop = '(?:<|=|>|<=|>=|!=|like|not\s+like|is\s+not|is)';
	my %boolopsym = ('and' => '&', 'or' => '|');

	my $indx = 0;

	my @P = ();
	@T = ();
	my @QS = ();

	$s=~s|\\\'|\x04|g;      #PROTECT "\'" IN QUOTES.
			$s=~s|\\\"|\x02|g;      #PROTECT "\"" IN QUOTES.

	#THIS NEXT LOOP STRIPS OUT AND SAVES ALL QUOTED STRING LITERALS 
	#TO PREVENT THEM FROM INTERFEARING WITH OTHER REGICES, IE. DON'T 
	#WANT OPERATORS IN STRINGS TO BE TREATED AS OPERATORS!

	$indx++ while ($s =~ s/([\'\"])([^\1]*?)\1/
			$QS[$indx] = $2; "\$QS\[$indx]"/e);

	for (my $i=0;$i<=$#QS;$i++)   #ESCAPE LDAP SPECIAL-CHARACTERS.
	{
		$QS[$i] =~ s/([\*\(\)\+\\\<\>])/\\$1/g;
		$QS[$i] =~ s/\\x(\d\d)/\\$1/g;   #CONVERT PERL HEX TO LDAP HEX (\X## => \##).
	}

	$indx = 0;	

	$indx++ while ($s =~ s/(\w+)\s*($relop)\s*(\$QS\[\d*\])/
			my ($one, $two, $three) = ($1, $2, $3);
			my ($regex) = 0;
			my ($opr) = $two;

			#CONVERT "NOT LIKE" AND "IS NOT" TO "!( = ).

			if ($two =~ m!(?:not\s+like|is\s+not)!i)
			{
				$two = '=';
				$regex = 2;
			}
			elsif ($two =~ m!(?:like|is)!i)  #CONVERT "LIKE" AND "IS" TO "=".
			{
				$two = '=';
				$regex = 1;
			}
			$P[$indx] = $one.$two.$three;   #SAVE EXPRESSION.
		
			#CONVERT SQL WILDCARDS INTO LDAP WILDCARDS IN OPERAND.
		
			my ($qsindx);
			if ($three =~ m!\$QS\[(\d+)\]!)
			{
				$qsindx = $1;
				if ($regex > 0)
				{
					if ($opr !~ m!is!i)
					{
						$QS[$qsindx] =~ s!\%!\*!g;     #FIX WILDCARD.  NOTE - NO FIX FOR "_"!
					}
				}
		
				#NEXT 2 LINES INVERT EXPN. IF "X = ''" OR "X IS NULL".
		
				$P[$indx] = "!($P[$indx])"  if ($regex == 2 || $opr eq '!=' || ($opr eq '=' && !length($QS[$qsindx])));  #INVERT EXPRESSION IF "NOT"!
				$P[$indx] =~ s!\!\=!\=!;   #AFTER INVERSION, FIX "!=" (NOT VALID IN LDAP!)
				$QS[$qsindx] = '*'  unless (length($QS[$qsindx]));
			}
			"\$P\[$indx]";
	/e);
	$tindx = 0;
	$s = &parseParins($s);

	for (my $i=0;$i<=$#T;$i++)
	{
		1 while ($T[$i] =~ s/(.+?)\s*\band\b\s*(.+)/\&\($1\)\($2\)/i);
		@l = ();
		@l = split(/\s*\bor\b\s*/i, $T[$i]);
		if ($#l > 0)
		{
			$T[$i] = '|';
			while (@l)
			{
				$T[$i] .= '('.shift(@l).')';
			}
		}
	}
	$s =~ s/AND/and/ig;
	$s =~ s/OR/or/ig;
	1 while ($s =~ s/(.+?)\s*\band\b\s*(.+)/\(\&\($1\)\($2\)\)/);
	@l = ();
	@l = split(/\s*\bor\b\s*/i, $s);
	if ($#l > 0)
	{
		$s = '|';
		while (@l)
		{
			$s .= '('.shift(@l).')';
		}
	}
	1 while ($s =~ s/\bnot\b\s*([^\s\)]+)?/\!\($1\)/);
	1 while ($s =~ s/\$T\[(\d+)\]/$T[$1]/g);
	$s =~ s/(\w+)\s+is\s+not\s+null?/$1\=\*/gi;
	$s =~ s/(\w+)\s+is\s+null?/\!\($1\=\*\)/gi;

	#CONVERT SQL WILDCARDS TO PERL REGICES.

	1 while ($s =~ s/\$P\[(\d+)\]/$P[$1]/g);
	$s =~ s/ +//g;
	1 while ($s =~ s/\$QS\[(\d+)\]/$QS[$1]/g);
	$s =~ s/\x04/\'/g;    #UNPROTECT AND UNESCAPE QUOTES WITHIN QUOTES.

	return $s;
}

sub parseParins
{
	my $s = shift;

	$tindx++ while ($s =~ s/\(([^\(\)]+)\)/
			$T[$tindx] = &parseParins($1); "\$T\[$tindx]"
	/e);
	return $s;
}

sub rollback
{
	my ($self) = @_;

	my ($status) = 1;
	my ($dbh) = $self->FETCH('ldap_dbh');
	my ($autocommit) = $dbh->FETCH('AutoCommit');

	$status = $dbh->rollback()  unless ($autocommit);

	$self->{dirty} = 0  if ($status > 0);
	return $status;
}

sub update
{
	my ($self, $csr, $query) = @_;
	my ($i, $path, $regex, $table, $extra, @attblist, $filter, $all_columns, $status);
	my ($psuedocols) = "CURVAL|NEXTVAL|ROWNUM";

    ##++
    ##  Hack to allow parenthesis to be escaped!
    ##--

	$query =~ s/\\([()])/sprintf ("%%\0%d: ", ord ($1))/ge;
	$path  =  $self->{path};
	$regex =  $self->{column};

	if ($query =~ /^update\s+($path)\s+set\s+(.+)$/io)
	{
		($table, $extra) = ($1, $2);

		#ADDED IF-STMT 20010418 TO CATCH 
		#PARENTHESIZED SET-CLAUSES (ILLEGAL IN ORACLE & CAUSE WIERD PARSING ERRORS!)

		if ($extra =~ /^\(.+\)\s*where/)
		{
			$errdetails = 'parenthesis around SET clause?';
			return (-504);
		}
		$table =~ tr/A-Z/a-z/  unless ($self->{CaseTableNames});  #JWT:TABLE-NAMES ARE NOW CASE-INSENSITIVE!
		$self->{file} = $table;

		my ($dbh) = $csr->FETCH('ldap_dbh');
		my ($ldap) = $csr->FETCH('ldap_ldap');
		my ($tablehash) = $dbh->FETCH('ldap_tables');
		return (-524)  unless ($tablehash->{$table});
		my ($base, $objfilter, $dnattbs, $allattbs, $alwaysinsert) = split(/\:/,$tablehash->{$table});

		$all_columns = {};

		$extra =~ s/\\\\/\x02/g;         #PROTECT "\\"
		#1$extra =~ s/\'\'/\x03\x03/g;    #PROTECT '', AND \'.
		$extra =~ s/\\\'/\x03/g;    #PROTECT '', AND \'.

		$extra =~ s/^\s+//;  #STRIP OFF SURROUNDING SPACES.
		$extra =~ s/\s+$//;

		#NOW TEMPORARILY PROTECT COMMAS WITHIN (), IE. FN(ARG1,ARG2).

		$column = $self->{column};
		$extra =~ s/($column\s*\=\s*)\'(.*?)\'(,|$)/
				my ($one,$two,$three) = ($1,$2,$3);
				$two =~ s|\,|\x05|g;
				$two =~ s|\(|\x06|g;
				$two =~ s|\)|\x07|g;
				$one."'".$two."'".$three;
		/eg;

		1 while ($extra =~ s/\(([^\(\)]*)\)/
				my ($args) = $1;
				$args =~ s|\,|\x05|g;
				"\x06$args\x07";
		/eg);
		@expns = split(',',$extra);
		for ($i=0;$i<=$#expns;$i++)  #PROTECT "WHERE" IN QUOTED VALUES.
		{
			$expns[$i] =~ s/\x05/,/g;
			$expns[$i] =~ s/\x06/\(/g;
			$expns[$i] =~ s/\x07/\)/g;
			$expns[$i] =~ s/\=\s*'([^']*?)where([^']*?)'/\='$1\x05$2'/gi;
			$expns[$i] =~ s/\'(.*?)\'/my ($j)=$1; 
					$j=~s|where|\x05|g; 
					"'$j'"
			/eg;
		}
		$extra = $expns[$#expns];    #EXTRACT WHERE-CLAUSE, IF ANY.
		$filter = ($extra =~ s/(.*)where(.+)$/where$1/i) ? $2 : '';
		$filter =~ s/\s+//;
		$expns[$#expns] =~ s/\s*where(.+)$//i;   #20000108 REP. PREV. LINE 2FIX BUG IF LAST COLUMN CONTAINS SINGLE QUOTES.
		$column = $self->{column};
		$objfilter ||= 'objectclass=*';
		$objfilter = "($objfilter)"  unless ($objfilter =~ /^\(/);
		if ($filter)
		{
			$filter = $self->parse_expression ($filter);
			$filter = '('.$filter.')'  unless ($filter =~ /^\(/);
			$filter = "(&$objfilter$filter)";
		}
		else
		{
			$filter = "$objfilter";
		}
		$alwaysinsert .= ',' . $base;
		$alwaysinsert =~ s/\\\\/\x02/g;   #PROTECT "\\"
		$alwaysinsert =~ s/\\\,/\x03/g;   #PROTECT "\,"
		$alwaysinsert =~ s/\\\=/\x04/g;   #PROTECT "\="
		my ($i1, $col, $vals, $j, @l);
		for ($i=0;$i<=$#expns;$i++)  #EXTRACT FIELD NAMES AND 
	                             #VALUES FROM EACH EXPRESSION.
		{
			$expns[$i] =~ s/\x03/\\\'/g;    #UNPROTECT '', AND \'.
			$expns[$i] =~ s/\x02/\\\\/g;    #UNPROTECT "\\".
			$expns[$i] =~ s!\s*($column)\s*=\s*(.+)$!
					my ($var) = $1;
					my ($val) = $2;
		
					$val = &pscolfn($self,$val)  if ($val =~ "$column\.$psuedocols");
					$var =~ tr/A-Z/a-z/;
					$val =~ s|%\0(\d+): |pack("C",$1)|ge;
					$val =~ s/^\'//;             #NEXT 2 ADDED 20010530 TO STRIP EXCESS QUOTES.
					$val =~ s/([^\\\'])\'$/$1/;
					$val =~ s/\'$//;
					$all_columns->{$var} = $val;
					@_ = split(/\,\s*/, $alwaysinsert);
					while (@_)
					{
						($col, $vals) = split(/\=/, shift);
						next  unless ($col eq $var);
						$vals =~ s/\x04/\\\=/g;       #UNPROTECT "\="
						$vals =~ s/\x03/\\\,/g;       #UNPROTECT "\,"
						$vals =~ s/\x02/\\\\/g;       #UNPROTECT "\\"
						@l = split(/\Q$self->{ldap_inseparator}\E/, $vals);
VALUE:							for (my $j=0;$j<=$#l;$j++)
						{
							next  if ($all_columns->{$var} =~ /\b$l[$j]\b/);
							$all_columns->{$var} .= $self->{ldap_inseparator} 
									if ($all_columns->{$var});
							$all_columns->{$var} .= $l[$j];
						}
					}
					$all_columns->{$var} =~ s/\x02/\\\\/g;
					$all_columns->{$var} =~ s/\x03/\'/g;   #20000108 REPL. PREV. LINE - NO NEED TO DOUBLE QUOTES (WE ESCAPE THEM) - THIS AIN'T ORACLE.
			!e;
		}

		delete $all_columns->{dn};   #DO NOT ALLOW DN TO BE CHANGED DIRECTLY!
		my ($data);
		my (@searchops) = (
				'base' => $base,
				'filter' => $filter,
				);
		foreach my $i (qw(ldap_sizelimit ldap_timelimit deref typesonly 
		callback))
		{
			$j = $i;
			$j =~ s/^ldap_//;
			push (@searchops, ($j, $self->{$i}))  if ($self->{$i});
		}
		push (@searchops, ('scope', ($self->{ldap_scope} || 'one')));
		$data = $ldap->search(@searchops) 
				or return($self->ldap_error($@,"Search failed to return object: filter=$filter (".$data->error().")"));
		my (@varlist) = ();
		$dbh = $csr->FETCH('ldap_dbh');
		my ($autocommit) = $dbh->FETCH('AutoCommit');
		my ($commitqueue) = $dbh->FETCH('ldap_commitqueue')  unless ($autocommit);
		my (@dnattbs) = split(/\,/, $dnattbs);
		my ($changedn);
		while (my $entry = $data->shift_entry())
		{
			$dn = $entry->dn();
			$dn =~ s/\\/\x02/g;     #PROTECT "\";
			$dn =~ s/\\\,/\x03/g;   #PROTECT "\,";
			$changedn = 0;
I:			foreach my $i (@dnattbs)
			{
				foreach my $j (keys %$all_columns)
				{
					if ($i eq $j)
					{
						$dn =~ s/(\b$i\=)([^\,]+)/$1$all_columns->{$j}/;
						$changedn = 1;
						next I;
					}
				}
			}
			$dn =~ s/(?:\,\s*)$base$//;
			$dn =~ s/\x03/\\\,/g;     #UNPROTECT "\,";
			$dn =~ s/\x02/\\/g;     #UNPROTECT "\";
			foreach my $i (keys %$all_columns)
			{
				$all_columns->{$i} =~ s/(?:\\|\')\'/\'/g;   #1UNESCAPE QUOTES IN VALUES.
				@_ = split(/\Q$self->{ldap_inseparator}\E/, $all_columns->{$i});
				if (!@_)
				{
					push (@attblist, ($i, ''));
				}
				elsif (@_ == 1)
				{
					push (@attblist, ($i, shift));
				}
				else
				{
					push (@attblist, ($i, [@_]));
				}
			}
			$r1 = $entry->replace(@attblist);
			if ($r1 > 0)
			{
				if ($autocommit)
				{
					$r2 = $entry->update($ldap);   #COMMIT!!!
					if ($r2->is_error)
					{
						$errdetails = $r2->code . ': ' . $r2->error;
						return (-523);
					}
					if ($changedn)
					{
						$r2 = $ldap->moddn($entry, newrdn => $dn);
						if ($r2->is_error)
						{
							$errdetails = "Could not change dn - " 
									. $r2->code . ': ' . $r2->error . '!';
							return (-523);
						}
					}
				}
				else
				{
					push (@{$commitqueue}, (\$entry, \$ldap));
					push (@{$commitqueue}, "dn=$dn")  if ($changedn);
				}
				++$status;
			}
			else
			{
			#return($self->ldap_error($@,"Search failed to return object: filter=$filter (".$data->error().")"));
				$errdetails = $data->code . ': ' . $data->error;
				return (-523);
			}
		}
		return ($status);
	}
	else
	{
		return (-504);
	}
}

sub delete 
{
	my ($self, $csr, $query) = @_;
	my ($path, $table, $filter, $status, $wherepart);

	$path = $self->{path};
	if ($query =~ /^delete\s+from\s+($path)(?:\s+where\s+(.+))?$/io)
	{
		$table     = $1;
		$wherepart = $2;
		$table =~ tr/A-Z/a-z/  unless ($self->{CaseTableNames});  #JWT:TABLE-NAMES ARE NOW CASE-INSENSITIVE!
		$self->{file} = $table;

		my ($dbh) = $csr->FETCH('ldap_dbh');
		my ($ldap) = $csr->FETCH('ldap_ldap');
		my ($tablehash) = $dbh->FETCH('ldap_tables');
		return (-524)  unless ($tablehash->{$table});
		my ($base, $objfilter, $dnattbs, $allattbs, $alwaysinsert) = split(/\:/,$tablehash->{$table});
		$objfilter ||= 'objectclass=*';
		$objfilter = "($objfilter)"  unless ($objfilter =~ /^\(/);
		if ($wherepart =~ /\S/)
		{
			$filter = $self->parse_expression ($wherepart);
			$filter = '('.$filter.')'  unless ($filter =~ /^\(/);
			$filter = "(&$objfilter$filter)";
		}
		else
		{
			$filter = "$objfilter";
		}
		$filter = '('.$filter.')'  unless ($filter =~ /^\(/);

		$data = $ldap->search(
				base   => $base,
				filter => $filter,
		) or return ($self->ldap_error($@,"Search failed to return object: filter=$filter (".$data->error().")"));
		my ($j) = 0;
		my (@varlist) = ();
		$dbh = $csr->FETCH('ldap_dbh');
		my ($autocommit) = $dbh->FETCH('AutoCommit');
		my ($commitqueue) = $dbh->FETCH('ldap_commitqueue')  unless ($autocommit);
		while (my $entry = $data->shift_entry())
		{
			$dn = $entry->dn();
			next  unless ($dn =~ /$base$/);
			$r1 = $entry->delete();
			if ($autocommit)
			{
				$r2 = $entry->update($ldap);   #COMMIT!!!
				if ($r2->is_error)
				{
					$errdetails = $r2->code . ': ' . $r2->error;
					return (-523);
				}
			}
			else
			{
				push (@{$commitqueue}, (\$entry, \$ldap));
			}
			++$status;
		}

		return $status;
	}
	else
	{
		return (-505);
	}
}

sub insert
{
	#my ($self, $query) = @_;
	my ($self, $csr, $query) = @_;
	my ($i, $path, $table, $columns, $values, $status);

	$path = $self->{path};
	if ($query =~ /^insert\s+into\s+    # Keyword
			($path)\s*                  # Table
			(?:\((.+?)\)\s*)?           # Keys
	values\s*                           # 'values'
			\((.+)\)$/ixo)
	{   #JWT: MAKE COLUMN LIST OPTIONAL!

		($table, $columns, $values) = ($1, $2, $3);
		my ($dbh) = $csr->FETCH('ldap_dbh');
		my ($tablehash) = $dbh->FETCH('ldap_tables');
		$table =~ tr/A-Z/a-z/  unless ($self->{CaseTableNames});  #JWT:TABLE-NAMES ARE NOW CASE-INSENSITIVE!
		$self->{file} = $table;
		return (-524)  unless ($tablehash->{$table});
		my ($base, $objfilter, $dnattbs, $allattbs, $alwaysinsert) = split(/\:/,$tablehash->{$table});
		$columns =~ s/\s//g;
		$columns ||= $allattbs;
		$columns = join(',', @{ $self->{order} })  unless ($columns =~ /\S/);  #JWT

		unless ($columns =~ /\S/)
		{
			return ($self->display_error (-509));
		}
		$values =~ s/\\\\/\x02/g;         #PROTECT "\\"
		$values =~ s/\\\'/\x03/g;    #PROTECT '', AND \'.

		$values =~ s/\'(.*?)\'/
				my ($j)=$1; 
				$j=~s|,|\x04|g;         #PROTECT "," IN QUOTES.
				"'$j'"
		/eg;
		@values = split(/,/,$values);
		$values = '';
		for $i (0..$#values)
		{
			$values[$i] =~ s/^\s+//;      #STRIP LEADING & TRAILING SPACES.
			$values[$i] =~ s/\s+$//;
			$values[$i] =~ s/\x03/\'/g;   #RESTORE PROTECTED SINGLE QUOTES HERE.
			$values[$i] =~ s/\x02/\\/g;   #RESTORE PROTECTED SLATS HERE.
			$values[$i] =~ s/\x04/,/g;    #RESTORE PROTECTED COMMAS HERE.
		}
		chop($values);

		$status = $self->insert_data ($csr, $base, $dnattbs, $alwaysinsert, $columns, @values);

		return $status;
	}
	else
	{
		return (-508);
	}
}

sub insert_data
{
	my ($self, $csr, $base, $dnattbs, $alwaysinsert, $column_string, @values) = @_;
	my (@columns, @attblist, $loop, $column, $j, $k);
	$column_string =~ tr/A-Z/a-z/;
	$dnattbs =~ tr/A-Z/a-z/;
	@columns = split (/,/, $column_string);

	if ($#columns = $#values)
	{
		my $dn = '';
		my @t = split(/,/, $dnattbs);
		while (@t)
		{
			$j = shift (@t);
J1:			for (my $i=0;$i<=$#columns;$i++)
			{
				if ($columns[$i] eq $j)
				{
					$dn .= $columns[$i] . '=';
					if ($values[$i] =~ /\Q$self->{ldap_inseparator}\E/)
					{
						$dn .= (split(/\Q$self->{ldap_inseparator}\E/,$values[$i]))[0];
					}
					else
					{
						$dn .= $values[$i];
					}
					$dn .= ', ';
					last J1;
				}
			}
		}
		$dn =~ s/\'//g;
		$dn .= $base;
		for (my $i=0;$i<=$#columns;$i++)
		{
			@l = split(/\Q$self->{ldap_inseparator}\E/,$values[$i]);
			while (@l)
			{
				$j = shift(@l);
				$j =~ s/^\'//;
				$j =~ s/([^\\\'])\'$/$1/;
				unless (!length($j) || $j eq "'" || $columns[$i] eq 'dn')
				{
					$j = "'"  if ($j eq "''");
					push (@attblist, $columns[$i]);
					push (@attblist, $j);
				}
			}
		}
		$alwaysinsert .= ',' . $base;
		my ($i1, $found, $col, $vals, $j);
		@_ = split(/\,\s*/, $alwaysinsert);
		while (@_)
		{
			($col, $vals) = split(/\=/, shift);
			@l = split(/\Q$self->{ldap_inseparator}\E/, $vals);
VALUE:				for (my $i=0;$i<=$#l;$i++)
			{
				for ($j=0;$j<=$#attblist;$j+=2)
				{
					if ($attblist[$j] eq $col)
					{
						next VALUE  if ($attblist[$j+1] eq $l[$i]);
					}
				}
				push (@attblist, $col);
				push (@attblist, $l[$i]);
			}
		}
		my ($ldap) = $csr->FETCH('ldap_ldap');

		my $entry = Net::LDAP::Entry->new;
		$entry->dn($dn);

		my $result = $entry->add(@attblist);
		$_ = $entry->dn();

		my ($dbh) = $csr->FETCH('ldap_dbh');
		my ($autocommit) = $dbh->FETCH('AutoCommit');
		if ($autocommit)
		{
			$r2 = $entry->update($ldap);   #COMMIT!!!
			if ($r2->is_error)
			{
				$errdetails = $r2->code . ': ' . $r2->error;
				return (-523);
			}
		}
		else
		{
			my ($commitqueue) = $dbh->FETCH('ldap_commitqueue');
			push (@{$commitqueue}, (\$entry, \$ldap));
		}

		return (1);
	}
	else
	{
		$errdetails = "$#columns != $#values";   #20000114
		return (-509);
	}
}						    

sub pscolfn
{
	my ($self,$id) = @_;
	return $id  unless ($id =~ /CURVAL|NEXTVAL|ROWNUM/);
	my ($value) = '';
	my ($seq_file,$col) = split(/\./,$id);
	$seq_file = $self->get_path_info($seq_file) . '.seq';

	$seq_file =~ tr/A-Z/a-z/  unless ($self->{CaseTableNames});  #JWT:TABLE-NAMES ARE NOW CASE-INSENSITIVE!
	open (FILE, "<$seq_file") || return (-511);
	$x = <FILE>;
	#chomp($x);
	$x =~ s/\s+$//;   #20000113
	($incval, $startval) = split(/,/,$x);
	close (FILE);
	if ($id =~ /NEXTVAL/)
	{
		open (FILE, ">$seq_file") || return (-511);
		$incval += ($startval || 1);
		print FILE "$incval,$startval\n";
		close (FILE);
	}
	$value = $incval;
	return $value;
}

sub SYSTIME
{
	return time;
}

sub NUM
{
	return shift;
}

sub NULL
{
	return '';
}

1;
