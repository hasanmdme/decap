//
// Generated by the Exaile Playlist Analyzer plugin.
// (C) 2014 Dustin Spicuzza <dustin@virtualroadside.com>
//
// This work is licensed under the Creative Commons Attribution 4.0
// International License. To view a copy of this license, visit
// http://creativecommons.org/licenses/by/4.0/.
//
// Inspired by http://www.findtheconversation.com/concept-map/
// Loosely based on https://bl.ocks.org/mbostock/4063550
//
var data = [];
data = [['cap_net_broadcast', []], ['cap_syslog', ['syslog']], ['cap_sys_pacct', ['acct']], ['cap_block_suspend', ['epoll_ctl']], ['cap_net_bind_service', ['bind']], ['cap_net_raw', ['socket']], ['cap_linux_immutable', ['ioctl']],['cap_lease', ['fcntl']], ['cap_audit_write', ['sendto']], ['cap_setfcap', ['clone']], ['cap_mac_override', ['socket']], ['cap_audit_read', ['bind']], ['cap_kill', ['ioctl', 'kill']], ['cap_setpcap', ['prctl', 'capset']], ['cap_net_admin', ['ioctl', 'setsockopt']], ['cap_sys_rawio', ['iopl', 'ioperm']], ['cap_sys_chroot', ['setns', 'chroot']], ['cap_sys_tty_config', ['ioctl', 'vhangup']], ['cap_wake_alarm', ['timer_create', 'timerfd_settime']], ['cap_fsetid', ['chmod', 'fchmod', 'fchmodat']], ['cap_sys_boot', ['reboot', 'kexec_load', 'kexec_file_load']], ['cap_mknod', ['renameat2', 'mknod', 'mknodat']], ['cap_mac_admin', ['setxattr', 'lsetxattr', 'fsetxattr']], ['cap_chown', ['chown', 'fchown', 'lchown', 'fchownat']], ['cap_sys_module', ['finit_module', 'init_module', 'create_module', 'delete_module']], ['cap_dac_read_search', ['open', 'openat', 'openat2', 'open_by_handle_at', 'linkat']], ['cap_setgid', ['setgroups', 'setfsgid', 'setgid', 'setregid', 'setresgid']], ['cap_setuid', ['keyctl', 'setuid', 'setreuid', 'setresuid', 'setfsuid']], ['cap_ipc_lock', ['mlock', 'mlock2', 'mlockall', 'mmap', 'memfd_create']], ['cap_sys_time', ['settimeofday', 'stime', 'adjtimex', 'clock_adjtime', 'ntp_adjtime']], ['cap_dac_override', ['open', 'openat', 'openat2', 'utime', 'utimensat', 'utimes']], ['cap_sys_ptrace', ['ptrace', 'set_robust_list', 'process_vm_readv', 'process_vm_writev', 'userfaultfd', 'kcmp']], ['cap_audit_control', ['sendto', 'send', 'sendmsg', 'recvmsg', 'recv', 'recvfrom']], ['cap_ipc_owner', ['msgctl', 'shmctl', 'msgget', 'msgrcv', 'semop', 'semtimedop', 'shmat', 'shmdt', 'msgsnd']], ['cap_sys_resource', ['ioctl', 'sendto', 'send', 'sendmsg', 'msgctl', 'setrlimit', 'fcntl', 'prctl', 'prlimit', 'mq_open']], ['cap_sys_nice', ['ioprio_set', 'nice', 'setpriority', 'sched_setscheduler', 'sched_setparam', 'sched_setattr', 'sched_setaffinity', 'migrate_pages', 'move_pages', 'spu_create', 'mbind']], ['cap_fowner', ['ioctl', 'open', 'openat', 'openat2', 'chmod', 'fchmod', 'fchmodat', 'utime', 'utimensat', 'utimes', 'unlink', 'unlinkat', 'fcntl', 'rename', 'renameat', 'renameat2', 'rmdir']], ['cap_sys_admin', ['ioctl', 'bpf', 'clone', 'perf_event_open', 'mount', 'umount', 'pivot_root', 'swapon', 'swapoff', 'sethostname', 'setdomainname', 'quotactl', 'vm86', 'lookup_dcookie', 'io_submit', 'msgctl', 'setrlimit', 'shmctl', 'ioprio_set', 'setns', 'fanotify_init', 'keyctl', 'madvise', 'nfsservctl', 'bdflush', 'unshare', 'seccomp', 'ptrace', 'prctl']]];

//data = [[]]
// transform the data into a useful representation
// 1 is inner, 2, is outer

// need: inner, outer, links
//
// inner: 
// links: { inner: outer: }


var outer = d3.map();
console.log('outer =', outer)
var inner = [];
var links = [];

var outerId = [0];
//var extent = d3.extent(data, d=>d.value)
//console.log('extent', extent)
data.forEach(function(d){
	//console.log('data d=', d)
	if (d == null)
		return;
	
	i = { id: 'i' + inner.length, name: d[0], related_links: [] };
	i.related_nodes = [i.id];
	inner.push(i);
	
	if (!Array.isArray(d[1]))
		d[1] = [d[1]];
	
	d[1].forEach(function(d1){
		
		o = outer.get(d1);
		
		if (o == null)
		{
			o = { name: d1,	id: 'o' + outerId[0], related_links: [] };
			o.related_nodes = [o.id];
			outerId[0] = outerId[0] + 1;	
			
			outer.set(d1, o);
		}
		
		// create the links
		l = { id: 'l-' + i.id + '-' + o.id, inner: i, outer: o }
		links.push(l);
		
		// and the relationships
		i.related_nodes.push(o.id);
		i.related_links.push(l.id);
		o.related_nodes.push(i.id);
		o.related_links.push(l.id);
	});
});


data = {
	inner: inner,
	outer: outer.values(),
	links: links
}
console.log('data = ',data)
// sort the data -- TODO: have multiple sort options
outer = data.outer;
data.outer = Array(outer.length);
//console.log()
var i1 = 0;
var i2 = outer.length - 1;

for (var i = 0; i < data.outer.length; ++i)
{
	if (i % 2 == 1)
		data.outer[i2--] = outer[i];
	else
		data.outer[i1++] = outer[i];
}

console.log(data.outer.reduce(function(a,b) { return a + b.related_links.length; }, 0) / data.outer.length);
/*
var caps = ['cap_sys_admin', 'cap_net_raw', 'cap_setuid']
// from d3 colorbrewer: 
// This product includes color specifications and designs developed by Cynthia Brewer (http://colorbrewer.org/).
var colors = ["#a50026","#d73027","#f46d43","#fdae61","#fee090","#ffffbf","#e0f3f8","#abd9e9","#74add1","#4575b4","#313695"]
var color = d3.scale.linear()
    .domain([10, 220])
    //.range([colors.length-1, 0])
    .range(['#ff3399'])
    //.clamp(true);
//console.log('color', color)
var color1 = d3.scale.ordinal()
    .domain(caps)
    .range(['yellow', 'blue', 'green']);
*/
var diameter = 1050;
var rect_width = 140;
var rect_height = 16;

var link_width = "1px"; 

var il = data.inner.length;
var ol = data.outer.length;
console.log("inner length and outer length", il, ol)
var inner_y = d3.scale.linear()
    .domain([0, il])
    .range([-(il * rect_height)/2, (il * rect_height)/2]);

mid = (data.outer.length/2.0)
console.log("here outer length mid", mid)
var outer_x = d3.scale.linear()
    .domain([0, mid, mid, data.outer.length])
    .range([15, 170, 190 ,350]); //mapping in the circle angle in degree..total 360 degree

var outer_y = d3.scale.linear()
    .domain([0, data.outer.length])
    .range([0, diameter / 2 - 120]);


// setup positioning
data.outer = data.outer.map(function(d, i) { 
    d.x = outer_x(i);
    d.y = diameter/2.5;//changed from 3 to 2.5
    //d.y = outer_y(i)
    return d;
});

data.inner = data.inner.map(function(d, i) { 
    d.x = -(rect_width / 2);
    d.y = inner_y(i);
    return d;
});


function get_color(name)
{
    console.log('color name', name)
    //name is string value for capability, need to convert this to decimal quivalent then pass it to next
    var c = Math.round(color(name));
    if (isNaN(c))
        //return '#dddddd';	// fallback color
        return '#1f77b4'
    
    return colors[c];
}
/*
function get_color(name)
{
    console.log('color name', name)
    //name is string value for capability, need to convert this to decimal quivalent then pass it to next
    var c = Math.round(color(name));
    if (isNaN(c))
        return '#dddddd';	// fallback color
    
    return colors[c];
}*/

// Can't just use d3.svg.diagonal because one edge is in normal space, the
// other edge is in radial space. Since we can't just ask d3 to do projection
// of a single point, do it ourselves the same way d3 would do it.  


function projectX(x)
{
    return ((x - 90) / 180 * Math.PI) - (Math.PI/2);
}

var diagonal = d3.svg.diagonal()
    .source(function(d) { return {"x": d.outer.y * Math.cos(projectX(d.outer.x)), 
                                  "y": -d.outer.y * Math.sin(projectX(d.outer.x))}; })            
    .target(function(d) { return {"x": d.inner.y + rect_height/2,
                                  "y": d.outer.x > 180 ? d.inner.x : d.inner.x + rect_width}; })
    .projection(function(d) { return [d.y, d.x]; });

var makefigure_x_pixeltop = 70;//mehedi
var makefigure_x_pixelleft = 0;//mehedi
var svg = d3.select("body").append("svg")
    .attr("width", diameter)
    .attr("height", diameter)
  .append("g")
    .attr("transform", "translate(" + (diameter-makefigure_x_pixelleft) / 2 + "," + (diameter-makefigure_x_pixeltop) / 2 + ")");
    

// links
var link = svg.append('g').attr('class', 'links').selectAll(".link")
    .data(data.links)
  .enter().append('path')
    .attr('class', 'link')
    .attr('id', function(d) { return d.id })
    .attr("d", diagonal)
    //.attr('stroke', function(d) { return get_color(d.inner.name); })
    .attr('stroke', '#585239')
    .attr('stroke-width', link_width);

// outer nodes

var onode = svg.append('g').selectAll(".outer_node")
    .data(data.outer)
  .enter().append("g")
    .attr("class", "outer_node")
    .attr("transform", function(d) { return "rotate(" + (d.x - 90) + ")translate(" + d.y + ")"; })
    .on("mouseover", mouseover)
    .on("mouseout", mouseout);
  
onode.append("circle")
    .attr('id', function(d) { return d.id })
    .style('cursor', "pointer")
    .attr("r", 4.5);
  
onode.append("circle")
    .attr('r', 9)
    .style('cursor', "pointer")
    .attr('visibility', 'hidden');
  
onode.append("text")
	.attr('id', function(d) { return d.id + '-txt'; })
    .attr("dy", ".31em")
    .style('cursor', "pointer")
    .attr("text-anchor", function(d) { return d.x < 180 ? "start" : "end"; })
    .attr("transform", function(d) { return d.x < 180 ? "translate(8)" : "rotate(180)translate(-8)"; })
    .text(function(d) { return d.name; });
    //.on("mouseover", mouseover)
   //.on("mouseout", mouseout);
  
// inner nodes
  
var inode = svg.append('g').selectAll(".inner_node")
    .data(data.inner)
  .enter().append("g")
    .attr("class", "inner_node")
    .attr("transform", function(d, i) { return "translate(" + d.x + "," + d.y + ")"})
    .on("mouseover", mouseover)
    .on("mouseout", mouseout);
  
inode.append('rect')
    .attr('width', rect_width)
    .attr('height', rect_height)
    .attr('id', function(d) { return d.id; });
    //.attr('fill', function(d) { return get_color(d.name); });
  
inode.append("text")
	.attr('id', function(d) { return d.id + '-txt'; })
    .attr('text-anchor', 'middle')
    .style('fill', 'white')
    .style('cursor', "pointer")
    .attr("transform", "translate(" + rect_width/2 + ", " + rect_height * .75 + ")")
    .text(function(d) { return d.name; });

// need to specify x/y/etc

d3.select(self.frameElement).style("height", diameter-150 + "px");

function mouseover(d)
{
	// bring to front
    //console.log('hei',o.related_nodes)
    console.log(d.related_nodes);
	d3.selectAll('.links .link').sort(function(a, b){ return d.related_links.indexOf(a.id); });	
	
    for (var i = 0; i < d.related_nodes.length; i++)
    {
        //console.log('each node',d.related_nodes[i])
        d3.select('#' + d.related_nodes[i]).classed('highlight', true).style('cursor', "pointer");
        if (d.related_nodes[i].includes('o')){
            d3.select('#' + d.related_nodes[i] + '-txt').attr("font-weight", 'bold').style('fill', "#3498db");
        }
    }
    
    for (var i = 0; i < d.related_links.length; i++)
        d3.select('#' + d.related_links[i]).attr('stroke-width', '4px').style('stroke', "#3498db");//
        //d3.select(this).style('stroke', 'green');
        //d3.select('#' + d.related_links[i]).style('fill', "green"); //mmmmnhnhnhnhnh--------
}

function mouseout(d)
{   	
    for (var i = 0; i < d.related_nodes.length; i++)
    {
        d3.select('#' + d.related_nodes[i]).classed('highlight', false);
        if (d.related_nodes[i].includes('o')){
            d3.select('#' + d.related_nodes[i] + '-txt').attr("font-weight", 'normal').style('fill', "black");
        }
    }
    
    for (var i = 0; i < d.related_links.length; i++)
        d3.select('#' + d.related_links[i]).attr('stroke-width', link_width).style('stroke', "#585239");
        //d3.select('#' + d.related_links[i]).attr('fill', 'green');
}

