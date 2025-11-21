---
layout: post
title: JS原型链污染漏洞检测
date: 2025-11-21 00:00 +0800
tags: [JavaScript, 原型链污染, 安全研究, 静态分析, Web安全]
mathjax: true
toc: true
---

JavaScript 是一种非常灵活的动态语言，核心机制之一就是原型链继承，但也引入了原型链污染漏洞。即攻击者通过原型链修改父类（上到 Object 类）的属性，影响所有对象行为。

<!--more-->

## 论文笔记

**Detecting Node.js Prototype Pollution Vulnerabilities via Object Lookup Analysis (2021)**

使用 AST 静态分析 JavaScript，难以精确地建模原型链继承和动态属性访问等行为，为了解决这个问题，论文提出一种 **Object Property Graph（OPG）**，新增 对象节点 和  属性/变量节点。（`object node`、`name node`）。

在 OPG 的基础上分析污点传播，将 Source 和 Sink 同时扩展，如果出现汇点，说明可能存在一条从输入到敏感属性的污染路径，之后约束求解验证。

```javascript
// JS 原型链污染示例
function merge(a,b){
    for(var p in b){
        try{
            if(b[p].constructor === Object){
                a[p] = merge(a[p],b[p]);
            } else{
                a[p] = b[p];
            }
        } catch(e){
            a[p] = b[p];
        }
    }
    return a;
}
// ......
var Paypal = function(config){
    if(!config.userId)
        throw new Error('Config must have userId');
    if(!config.password)
        throw new Error('Config must have password');
    // ......
    this.config = merge(defaultConfig,config);
};
// ......
module.exports = Paypal;
```

这份示例代码：`merge` 函数递归合并 `b` 到 `a`，但是没过滤 `__proto__` 、 `prototype`、 `constructor ` 这三个键。

调用：`merge(defaultConfig,config)` ，其中 `config` 用户可控，则可以通过这些键访问修改 `defaultConfig` 的原型对象。

### PoC

```javascript
var PayPal = require('paypal-adaptive');
var p = new PayPal(JSON.parse('{"__proto__":{"toString":"polluted"},"userId":"foo","password":"bar","signature":"abcd","appId":"1234","sandbox":"1234"}'));
console.log(({}).toString);
```

### 1.OPG

![OPG示例图](/assets/img/JS原型链污染/1.png)

左边是 Sink ，右边是 Source，中间的 蓝色箭头 赋值边，表示可控输入从 Source Cluster 赋值污染到 Sink Cluster

`*` 通配符节点表示用户可控的任何输入。

第一轮递归 p 赋值 为 `__proto__` ，第二轮递归 p 赋值为 `toString`，第三轮递归完成对这个`toString` 赋值  `toString = b['__proto__']['toString']` 。

通过 OPG，能够清晰地描绘出数据如何在不同对象和它们的属性之间流动，具备精确分析的基础。



### 2.对象查找分析 Object Lookup Analysis

#### 2.Source Cluster Expansion

**目标：** 识别并构建一个“受攻击者控制”的数据源的集合。

污点源一般来源于用户输入， 输入内容可能是任何对象，使用通配符 `*` 表示，这个对象的任意属性也认为是 `*` 。

如果访问 `source[*]` 说明 `source ` 可能有任意属性，这样实现扩展 Source Cluster



#### 3.Sink Cluster Expansion

**目标：** 识别并构建一个“被污染的目标”的集合。

Sink 是污染目标，初始化为 JavaScript 内置函数的原型（如 `Object.prototype`）。

当分析过程中遇到对敏感属性的读取操作时，分析器会主动将该对象原型链上的节点也纳入 Sink 集合，以此来捕获间接的污染行为。



#### 4.Constraint Collection and Solving

当 Source Cluster 扩展产生了通配符 (*) 属性，Sink Cluster 确定了需要访问的敏感函数和对应的原型链路径：

尝试将 Source 中通配符节点 与 Sink 中原型链节点对齐。

使用一个约束求解器判断所有的对齐条件是否能同时成立。

如上图将 第一轮递归的 p 与   `__proto__`  对齐，第二轮递归的 p 与  `toString` 对齐



## ObjLupAnsys 源码分析

> 源码比较多，借助 AI 帮我理清项目结构，通过跟踪工作流程，贴出关键代码，简明解释 ObjLupAnsys 具体如何实现。

### 1.OPG 的构建

首先使用 `Esprima` (https://esprima.org/)  解析 JavaScript 生成 AST

基于 AST 构建 OPG：深度优先遍历 AST，每个节点调用对应 Handler，负责将 AST 节点转换成 OPG 中的对应结构

```python
def __init__(self, G):
    self.G = G
    self.handler_map = {
            'File': self.HandleFile,
            'Directory': self.HandleFile,
            'AST_TOPLEVEL': self.HandleToplevel,
            'AST_ASSIGN': self.HandleAssign,
            'AST_CALL': self.HandleASTCall,
            'AST_METHOD_CALL': self.HandleASTCall,
            'AST_METHOD': self.HandleMethod,
            'AST_NEW': self.HandleASTCall,
            'AST_NAME': self.HandleVar,
            'AST_VAR': self.HandleVar,
            'AST_PROP': self.HandleProp,
            'AST_DIM': self.HandleProp,
            'AST_CONST': self.HandleVar,
            'integer': self.HandleConst,
            'string': self.HandleConst,
            'double': self.HandleConst,
            'AST_FUNC_DECL': self.HandleFuncDecl,
            'AST_CLOSURE': self.HandleFuncDecl,
            'AST_ARRAY': self.HandleArray,
            'AST_ARRAY_ELEM': self.HandleArrayElem,
            'AST_UNARY_OP': self.HandleUnaryOp,
            'AST_FOR': self.HandleFor,
            'AST_WHILE': self.HandleWhile,
            'AST_FOREACH': self.HandleForEach,
            'AST_BREAK': self.HandleBreak,
            'AST_EXPR_LIST': self.HandleExprList,
            'AST_PRE_INC': self.HandleIncDec,
            'AST_POST_INC': self.HandleIncDec,
            'AST_PRE_DEC': self.HandleIncDec,
            'AST_POST_DEC': self.HandleIncDec,
            'AST_IF': self.HandleIf,
            'AST_IF_ELEM': self.HandleIfElem,
            'AST_CONDITIONAL': self.HandleConditional,
            'AST_BINARY_OP': self.HandleBinaryOP,
            'AST_SWITCH': self.HandleSwitch,
            'AST_SWITCH_LIST': self.HandleSwitchList,
            'AST_RETURN': self.HandleReturn,
            'AST_TRY': self.HandleTry,
            'NULL': self.HandleNULL,
            'AST_THROW': self.HandleThrow,
            'AST_CATCH_LIST': self.HandleCatchList,
            'AST_CONTINUE': self.HandleContinue,
            'AST_STMT_LIST': self.HandleStmtList,
            'AST_ASSIGN_OP': self.HandleAssignOP,
            'AST_ENCAPS_LIST': self.HandleEncapsList,
            'AST_CLASS': self.HandleClass,
            }
```

下面是源码中的 Handler 类，是所有 handler 的父类，在每个 handler 中，会调用 重写的 process 函数，

```python
class Handler(object):
    """
    this is the parent class for all the handlers, including a 
    process method, a post_successors method.
    """
    def __init__(self, G: Graph, node_id: str, extra=None):
        from src.plugins.manager_instance import internal_manager as internal_manager
        self.internal_manager = internal_manager
        self.G = G
        self.node_id = node_id
        self.extra = extra

    def process(self):
        """
        for each handler, we should have a pre processing 
        method, which will actually run the node handle process.
        If the handling process can be finished in one function,
        we do not need further functions
        """
        print("Unimplemented Process Function")
        pass
```

以 `src/plugins/internal/array.py` 为例，

```python
class HandleArray(Handler):
    # 创建对象节点，并递归处理每一个子节点
    # ......

class HandleArrayElem(Handler):
    def process(self):
        if not (self.extra and self.extra.parent_obj is not None):
            loggers.main_logger.error("AST_ARRAY_ELEM occurs outside AST_ARRAY")
            return None
        else:
            try:
                # 获取 key 和 value 的 AST 节点
                value_node, key_node = self.G.get_ordered_ast_child_nodes(self.node_id)
            except:
                return NodeHandleResult()
            key = self.G.get_name_from_child(key_node) 
            if key is not None:
                key = key.strip("'\"")
            else:
                key = self.G.get_node_attr(self.node_id).get('childnum:int') 
            if key is None:
                key = wildcard 
            handled_value = self.internal_manager.dispatch_node(value_node, self.extra)
            value_objs = to_obj_nodes(self.G, handled_value, self.node_id)
            
            # 建立属性边
            for obj in value_objs:
                self.G.add_obj_as_prop(
                    key,                               # 属性名
                    self.node_id,                      # AST节点
                    parent_obj=self.extra.parent_obj,  # HandleArray 创建的对象节点 
                    tobe_added_obj=obj                 # 值对象
                )
        return NodeHandleResult(obj_nodes=value_objs,
            callback=get_df_callback(self.G))

    
class HandleUnaryOp(Handler):
    # 处理一元操作
    # ......
```

`HandleArray` 创建一个 对象节点，`HandleArrayElem` 建立属性边



在 DFS 遍历完 AST 之后，OPG 就构建成功。 



### 2.Source and Sink Cluster Expansion

Sink 初始化：定义初始 Sink 集合，为 Javascript 内置对象的原型。 

```python
# src/plugins/internal/setup_env.py
# ......
    G.builtin_prototypes = [
        G.object_prototype, G.string_prototype,
        G.array_prototype, G.function_prototype,
        G.number_prototype, G.boolean_prototype, G.regexp_prototype
    ]
    # 将内置属性视为 Sink 
    G.pollutable_objs = set(chain(*
        [G.get_prop_obj_nodes(p) for p in G.builtin_prototypes]))
    G.pollutable_name_nodes = set(chain(*
        [G.get_prop_name_nodes(p) for p in G.builtin_prototypes]))
```



`handle_prop` ：`find_prop` 的入口，同时进行 Source 、Sink Cluster Expansion

```python
# src/plugins/internal/handlers/property.py
def handle_prop(G, ast_node, side=None, extra=ExtraInfo()) \
    -> (NodeHandleResult, NodeHandleResult):
    # recursively handle both parts
	# ......
    # prepare property names
    prop_names, prop_name_sources, prop_name_tags = to_values(G, handled_prop, for_prop=True)
    
    # 判断属性名的来源中有污点，属性名也为污点
    name_tainted = False
    key_objs = handled_prop.obj_nodes 
    if G.check_proto_pollution or G.check_ipt:
        for source in chain(*prop_name_sources):
            if G.get_node_attr(source).get('tainted'):
                name_tainted = True
                break

	# 判断父对象是否是内置原型
    # 是内置原型 → 添加到 Sink
    parent_is_proto = False
    if G.check_proto_pollution or G.check_ipt:
        for obj in handled_parent.obj_nodes:
            if obj in G.builtin_prototypes:
                parent_is_proto = True
                break

    # create parent object if it doesn't exist
	# ......
    
    # 遍历所有属性名，查找对应的 name 节点的 object 节点
    for i, prop_name in enumerate(prop_names):
        assert prop_name is not None
        # 递归查找
        name_nodes, obj_nodes, found_in_proto, proto_is_tainted = \
            find_prop(G, parent_objs, 
            prop_name, branches, side, parent_name,
            prop_name_for_tags=prop_name_tags[i],
            ast_node=ast_node, prop_name_sources=prop_name_sources[i])
        prop_name_nodes.update(name_nodes) # 收集到的 name 节点
        prop_obj_nodes.update(obj_nodes)  # 收集到的 object 节点

        if prop_name == wildcard:
            multi_assign = True
        
        # 内部属性篡改 IPT 检测逻辑
        if G.check_ipt and side != 'left' and (proto_is_tainted or \
                (found_in_proto and parent_is_tainted) or \
                parent_is_prop_tainted):
                # second possibility, parent is prop_tainted
            tampered_prop = True
            G.ipt_use.add(ast_node)
            if G.exit_when_found:
                G.finished = True
            
            if 'ipt' not in G.detection_res:
                G.detection_res['ipt'] = set()

            ipt_type = 0
            if found_in_proto and parent_is_tainted:
                ipt_type = "Prototype hijacking" # 原型劫持
            elif parent_is_prop_tainted:
                ipt_type = "App parent is prop tainted" # 父对象属性被污染
            else:
                ipt_type = "proto is tainted"  # 原型被污染
            detailed_info = "ipt detected in file {} Line {} node {} type {}".format(\
                    G.get_node_file_path(ast_node), 
                    G.get_node_attr(ast_node).get('lineno:int'),
                    ast_node,
                    ipt_type
                    )
			# 记录检测信息
            # ......

    # 找不到任何对象，则默认为 undefined 对象
    if not prop_obj_nodes:
        prop_obj_nodes = set([G.undefined_obj])

    # return ......
```

**Source Cluster Expansion：** 检查 `prop_name_sources` 的 `tainted` 标记，识别用户可控的属性名，加入到 Source

**Sink Cluster Expansion：** 检查 `parent_obj` 是否属于 `builtin_prototypes`，直接识别对敏感原型的访问。如果检测到代码正在访问内置原型的属性，将此次访问标记为 Sink 





### **3. Object Lookup Analysis**

`find_prop` 进行对象查找分析

```python
def find_prop(G, parent_objs, prop_name, branches=None,
    side=None, parent_name='Unknown', in_proto=False, depth=0,
    prop_name_for_tags=None, ast_node=None, prop_name_sources=[]):
    '''
    递归地在父对象及其 __proto__ 链中查找属性
    '''
    # 限制递归深度，防止无限递归
    if depth == 5:
        return [], [], None, None
    
    prop_name_nodes = set()  # 找到的属性名节点
    prop_obj_nodes = set()   # 找到的属性对象节点
    proto_is_tainted = False # 原型是否被污染的标志
    found_in_proto = False   # 是否在原型链中找到的标志

    # 遍历每个父对象
    for parent_obj in parent_objs:
        # 如果属性名是通配符且对象不是通配符对象，且不检查原型污染/IPT，则跳过
        if prop_name == wildcard and not is_wildcard_obj(G, parent_obj) and \
            not G.check_proto_pollution and not G.check_ipt:
            continue

        # 如果在原型链中搜索，检查原型污染状态
        if in_proto:
            found_in_proto = True
            if G.get_node_attr(parent_obj).get('tainted'):
                proto_is_tainted = True
                loggers.main_logger.debug(f'__proto__ {parent_obj} is tainted.')

        name_node_found = False    # 是否找到具体名称节点的标志
        wc_name_node_found = False # 是否找到通配符名称节点的标志

        # 1. 首先搜索"直接"属性（非通配符的具体属性名）
        prop_name_node = G.get_prop_name_node(prop_name, parent_obj)
        if prop_name_node is not None and prop_name != wildcard:
			# ......

        # 2. 如果直接属性未找到，在 __proto__ 链中搜索
        elif prop_name != '__proto__' and prop_name != wildcard:
			# ......

        # 3. 如果属性名是通配符，获取所有属性
        if not in_proto and prop_name == wildcard:
			# ......

        # 4. 如果找不到具体属性，尝试通配符 (*)，为通配符对象建立污点传播边
        if (not in_proto or G.check_ipt) and prop_name != wildcard and (
                not name_node_found or G.check_proto_pollution or G.check_ipt):
			# ......

        # 5. 处理类型转换：将通配符对象转换为特定类型
        if (not in_proto and not name_node_found) and is_wildcard_obj(G, parent_obj):
			# ......
           
        # 6a. 如果未找到，创建通配符 属性名节点以及对象节点，并标记污点，建立污点传播边
        if ((not in_proto or G.check_ipt) and is_wildcard_obj(G, parent_obj)
                and not wc_name_node_found and G.get_node_attr(parent_obj)['type'] == 'object' 
                and (side != 'left' or prop_name == wildcard)):
            # ......
            
        # 6b. 普通对象和具体属性名的处理
        elif not in_proto and ((not name_node_found and prop_name != wildcard)
                or (not wc_name_node_found and prop_name == wildcard)):
			# ......
    
    # 只有当找到属性名节点时，才认为在原型中找到了属性
    found_in_proto = found_in_proto and len(prop_name_nodes) != 0
    if found_in_proto:
        loggers.main_logger.info("{} found in prototype chain".format(prop_name))
    
    return prop_name_nodes, prop_obj_nodes, found_in_proto, proto_is_tainted
```

第二步 模拟原型链查找，获取未找到属性的 `__proto__` 并递归调用自身，实现原型链查找

第三、四、五、六步处理通配符，处理用户输入的未知属性（ Source Cluster Expansion ），如果属性不存在，会在 OPG 中创建新的属性节点，模拟 Javascript 动态添加属性的行为。





污点传播：`add_contributes_to` ，当数据从一个节点流向另一个节点，比如赋值操作时，在 OPG 中添加 `CONTRIBUTES_TO` 数据流边，并将 `tainted`标记 从源节点传递到目标节点。

```python
def add_contributes_to(G: Graph, sources, target, operation: str=None,
    index: int=None, rnd: str=None, chain_tainted=True):
    # ...
    tainted = False
    for i, source in enumerate(sources):
        # ...
        G.add_edge(source, target, attr) # 添加数据流边
        # 检查源节点是否被污染
        tainted = tainted or G.get_node_attr(source).get('tainted', False)
    
    # 如果源被污染，则将污染传递给目标节点
    if chain_tainted and tainted:
        G.set_node_attr(target, ('tainted', True))
```



### 4.Constraint Collection and Solving

当分析器检测到一个潜在的原型链污染时，需要收集从 Source到 Sink 的完整路径，并对其进行验证。



路径回溯：`traceback` 从 Sink 开始，沿着数据流边反向追溯，构建完整的污染链。

```python
def traceback(G, vul_type, start_node=None):
    res_path = ""
    ret_pathes = []
    caller_list = []
    if vul_type == "proto_pollution":
        # 从漏洞触发点开始
        if start_node is not None:
            start_cpg = G.find_nearest_upper_CPG_node(start_node)
            # 沿 OBJ_REACHES 进行 DFS，反向追溯数据来源 
            pathes = G._dfs_upper_by_edge_type(start_cpg, "OBJ_REACHES")

            for path in pathes:
                ret_pathes.append(path)
                path.reverse()
                res_path += get_path_text(G, path, start_cpg)
            
            return ret_pathes, res_path, caller_list
	
    # 其他污染
    expoit_func_list = signature_lists[vul_type] # 敏感函数签名列表

    func_nodes = G.get_node_by_attr('type', 'AST_METHOD_CALL')
    func_nodes += G.get_node_by_attr('type', 'AST_CALL')
    
	# 遍历 AST 中所有函数调用点，识别可能被利用的危险调用点，作为约束求解的目标点。
    for func_node in func_nodes:
        # we assume only one obj_decl edge
        func_name = G.get_name_from_child(func_node)
        if func_name in expoit_func_list:  
            caller = func_node
            caller = G.find_nearest_upper_CPG_node(caller)
            caller_list.append("{} called {}".format(caller, func_name))
            pathes = G._dfs_upper_by_edge_type(caller, "OBJ_REACHES")

            for path in pathes:
                ret_pathes.append(path)
                path.reverse()
                res_path += get_path_text(G, path, caller)
    return ret_pathes, res_path, caller_list
```



约束验证：收集到的路径需要经过验证，以排除误报。`check` 函数作为验证入口，根据约束对路径进行检查。

```python
def check(self, path):
    """
    select the checking function and run it based on the key value
    Return:
        the running result of the obj
    """
    key_map = {
            "exist_func": self.exist_func,
            "not_exist_func": self.not_exist_func,
            "start_with_func": self.start_with_func,
            "not_start_with_func": self.not_start_with_func,
            "start_within_file": self.start_within_file,
            "not_start_within_file": self.not_start_within_file,
            "end_with_func": self.end_with_func,
            "has_user_input": self.has_user_input,
            "start_with_var": self.start_with_var
            }

    if self.key in key_map:
        check_function = key_map[self.key]
    else:
        return False

    return check_function(self.value, path)
```

- `has_user_input` 会检查路径的起点是否是已知的用户输入源（如 `http.request`）
- `exist_func` 会检查路径中是否经过了某个特定的函数（如易受攻击的 `merge` 函数）

只有当一条污染路径满足所有预设的约束条件时，系统才会最终将其报告为一个真实可信的漏洞。



## CVE 分析

```
ini-parser		0.0.2		index.js(Line 14)		CVE-2020-7617
```

> [Prototype Pollution in ini-parser | CVE-2020-7617 | Snyk](https://security.snyk.io/vuln/SNYK-JS-INIPARSER-564122)

`ini-parser` 是一个解析 .ini 文件的包

```shell
npm i ini-parser@0.0.2
```



### 正常使用

```ini
[database]
host = localhost
port = 3306
username = admin
password = secret123
database_name = testdb

[server]
host = 0.0.0.0
port = 8080
debug = true

[logging]
level = INFO
file_path = ./logs/app.log
```

```javascript
var parser = require('ini-parser');
console.log(parser.parseFileSync('./CVE/test.ini'))
```

![正常使用ini-parser](/assets/img/JS原型链污染/2.png)



### PoC

```ini
[__proto__]
toString=hacked
```

```javascript
var parser = require('ini-parser');
console.log(parser.parseFileSync('./CVE/test.ini'))
// 检查一下是否成功污染 Object
console.log({}.toString);
```

![PoC验证结果](/assets/img/JS原型链污染/3.png)



### 源码分析

`index.js` ：

```javascript
// const fs = require('fs');
var REG_GROUP = /^\s*\[(.+?)\]\s*$/
var REG_PROP = /^\s*([^#].*?)\s*=\s*(.*?)\s*$/

function parse(string){
	var object = {}
	var lines = string.split('\n')
	var group
	var match
    
	// 逐行解析
	for(var i = 0, len = lines.length; i !== len; i++){
        // 匹配组名，即为 group，与 Object[group_name] 指向同一对象
		if(match = lines[i].match(REG_GROUP))
			object[match[1]] = group = object[match[1]] || {};
        // 匹配属性，group[key]=value
		else if(group && (match = lines[i].match(REG_PROP)))
			group[match[1]] = match[2];
	}

	return object;
}

function parseFile(file, callback){
	fs.readFile(file, 'utf-8', function(error, data){
		if(error)
			return callback(error);

		callback(null, parse(data))
	})
}


function parseFileSync(file){
	return parse(fs.readFileSync(file, 'utf-8'))
}

module.exports = {
	parse: parse,
	parseFile: parseFile,
	parseFileSync: parseFileSync
}
```

原型链污染：匹配组名和属性时没有限制，导致创建对象和属性时可以使用 `__proto__` ，`constructor`，`prototype` 通过原型链污染原型对象。



### 使用 ObjLupAnsys 检测

```shell
python3 ./ObjLupAnsys.py --nodejs -a --timeout 300 -q ../node_modules/ini-parser/
```

![ObjLupAnsys检测结果](/assets/img/JS原型链污染/4.png)

可以看到成功检测到了这个原型链污染。

