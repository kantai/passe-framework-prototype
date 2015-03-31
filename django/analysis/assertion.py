from django.htoken import verify_signature
from django.htoken import ACTIVE_USER_ID_KEY, PERMISSION_IDS, SUPER_STATUS

class ActiveUserAssert():
    def __init__(self, argument_position):
        self.position = argument_position
    def printerr(self, arg_list, token):
        return "User: args[%s] :: %s == %s" % \
            (self.position, arg_list[self.position], token.dict['hachi_active_user'])
    def check_assert(self, arg_list, token):
        # get active user?
        return arg_list[self.position] == token.dict['hachi_active_user']
    def __eq__(self, other):
        return ((isinstance(other, ActiveUserAssert) and  
                 other.position == self.position))
    def __repr__(self):
        return "User(%s)" % (self.position)
    def __hash__(self):
        return hash("U%s" % self.position)

class NullAssert():
    def __init__(self, argument_position):
        self.position = argument_position
    def check_assert(self, arg_list, token):
        return true
    def __eq__(self, other):
        return ((isinstance(other, NullAssert) and  
                 other.position == self.position))
    def __repr__(self):
        return "Null(%s)" % (self.position)
    def __hash__(self):
        return hash("N%s" % self.position)

def perm_validity_check(tdict, perms):
    return ( (tdict.get(SUPER_STATUS, 0) == 1) or
             (PERMISSION_IDS in tdict and \
                  all([ p in tdict[PERMISSION_IDS] for p in perms if p is not None ])) )

class ControlFlowAssert():
    def __init__(self, key, value):
        self.key = key
        self.value = value
    def __eq__(self, other):
        return ((isinstance(other, ControlFlowAssert) and
                 other.key == self.key and
                 other.value == self.value))
    def __hash__(self):
        return hash(self.__repr__())
    def __repr__(self):
        return "CF(%s, %s)" % (self.key, self.value)
    def printerr(self, arg_list, token):
        token_value_0 = token.dict.get(self.key)
        token_value_1 = token.dict.get(self.value)
        return "CF: t[%s] == t[%s] :: %s == %s" % \
            (self.key, self.value, token_value_0, token_value_1)
    def check_assert(self, arg_list, token):
        try:
            token_value_0 = token.dict[self.key]
            token_value_1 = token.dict[self.value]
        except KeyError:
            return False
        if isinstance(token_value_1, list) and isinstance(token_value_0, list):
            l1 = set([unicode(v) for v in token_value_1])
            l0 = set([unicode(v) for v in token_value_0])
            return l0.issubset(l1) or l1.issubset(l0)
            
        elif isinstance(token_value_1, list):
            return (unicode(token_value_0) in [unicode(v) for v in token_value_1])
        elif isinstance(token_value_0, list):
            return (unicode(token_value_1) in [unicode(v) for v in token_value_0])
        else:
            return unicode(token_value_0) == unicode(token_value_1)

class PermissionAssert():
    def __init__(self, perms, valid):
#        self.position = -1
        self.perms = perms
        self.valid = valid
    def printerr(self, arg_list, token):
        return self.__repr__
    def check_assert(self, arg_list, token):
        validity = perm_validity_check(token.dict, self.perms) 
        return validity == self.valid
    def __eq__(self, other):
        return ((isinstance(other, PermissionAssert) and  
                 other.perms == self.perms and 
                 other.valid == self.valid))
    def __repr__(self):
        return "Perm(%s)" % (self.perms)
    def __hash__(self):
        return hash("P%s" % self.perms)

class ConstantAssert():
    def __init__(self, argument_position, value):
        """
        Values must be a list, guys!
        """
        self.position = argument_position
        self.value = value
    def printerr(self, arg_list, token):
        return "Cons: args[%s] == %s :: %s == %s" % \
            (self.position, self.value , arg_list[self.position], self.value)
    def check_assert(self, arg_list, token):
        r = ("%s" % arg_list[self.position]) == ("%s" % self.value)
        return r
    def __repr__(self):
        return "Constant(%s, %s)" % (self.position, self.value)
    def __hash__(self):
        return hash("C%s+%s" % (self.position, self.value))
    def __eq__(self, other):
        return (isinstance(other, ConstantAssert) and 
                other.position == self.position and
                other.value == self.value)

class TokenAssert():
    def __init__(self, argument_position, index):
        """
        index may be a tuple (in the case of a db response value)
        """
        self.position = argument_position
        self.index = index

    def _atom_check(self, val_arg, token_ix, token):
        """
        Evaluates the token constraint for a single token index
        """
        try:
            val_arg = unicode(val_arg)
            val_token = token.dict[token_ix]
            if isinstance(val_token, list):
                val_token = [unicode(i) for i in val_token]
                return (val_arg in val_token)
            val_token = unicode(val_token)
            return (val_arg == val_token)
        except KeyError:
            return False
    def printerr(self, arg_list, token):
        if isinstance(self.index, list):
            ix_out = [token.dict.get(ix) for ix in self.index]
        else:
            ix_out = token.dict.get(self.index)

        return "DFlow: args[%s] == t[%s] :: %s == %s" % \
            (self.position, self.index , arg_list[self.position], 
             ix_out)

    def _check_impl(self, val_arg, token):
        if isinstance(self.index, list):
            return any([self._atom_check(val_arg, ix, token) 
                        for ix in self.index])
        else:
            return self._atom_check(val_arg, self.index, token)


    def check_assert(self, arg_list, token):
        if not verify_signature(token):
            return False
        val_arg = arg_list[self.position]
        if isinstance(val_arg, list):
            return all([self._check_impl(v, token) for v in val_arg])
        else:
            return self._check_impl(val_arg, token)

    def __repr__(self):
        return "Token(%s, %s)" % (self.position, self.index)
    def __hash__(self):
        return hash("P%s+%s" % (self.position, self.index))
    def __eq__(self, other):
        return (isinstance(other, TokenAssert) and
                other.position == self.position and
                other.index == self.index)

