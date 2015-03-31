import re

__limit_pattern = re.compile('(^.* LIMIT )([0-9]+)$')
__offlimit_pattern = re.compile('(^.* LIMIT )([0-9]+)( OFFSET )([0-9]+)$')
def parameterize_limit(query, params):
    (query, params) = parameterize_in_set(query, params)

    re_match = __limit_pattern.match(query)
    if not re_match:
        return parameterize_offlimit(query, params)
    res_q = re_match.group(1) + "?"
    limit_param = re_match.group(2)
    try:
        limit_param = int(limit_param)
    except ValueError:
        pass
    if params:
        return (res_q, params + (limit_param, ))
    else:
        return (res_q, (limit_param, ))

def parameterize_offlimit(query, params):
    re_match = __offlimit_pattern.match(query)
    if not re_match:
        return (query, params)
    res_q = re_match.group(1) + "?"
    limit_param = re_match.group(2)
    try:
        limit_param = int(limit_param)
    except ValueError:
        pass
    if params:
        return (res_q, params + (limit_param, ))
    else:
        return (res_q, (limit_param, ))

__in_set_pattern = re.compile('(^.* IN )(\\((?:\\?, )*\\?\\))(.*)$')

def parameterize_in_set(query, params):
    re_match = __in_set_pattern.match(query)
    if not re_match:
        return (query, params)
    begin_q = re_match.group(1)
    in_params = re_match.group(2)
    end_q = re_match.group(3)
    assert begin_q + in_params + end_q == query
    skip_ix = begin_q.count("?")
    n_params = in_params.count("?")
    assert len(params) == skip_ix + n_params + end_q.count("?")
    front_params = params[:skip_ix] 
    munged_params = list(params[skip_ix:n_params+skip_ix])
    back_params = params[n_params+skip_ix:]
    assert front_params + tuple(munged_params) + back_params == params
    
    out_q = begin_q + " ? " + end_q
    out_p = front_params + (munged_params, ) + back_params
    
    return (out_q, out_p)
