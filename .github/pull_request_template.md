# Describe your changes

... Enter a description of your changes here ...

## Checklist before requesting a review

**Quality**
- [ ] I have performed a self-review of my code
- [ ] Doctests are present according to the style guide (below)

**Admin**
- [ ] I have labelled this PR correctly
  - [ ] App (if any)
  - [ ] effort (required)
  - [ ] work (required)
  - [ ] stream (required)
  - [ ] priority (required)
  - [ ] type (required)
  - [ ] status (required)
- [ ] I have linked this PR to the correct Project
- [ ] I have linked this PR to all relevant issues *(can only be done after creation)*

-------------------
# Style Guide - Please leave this in the PR

## Breaking Changes
If this PR introduces breaking changes please list apps that will be affected and the associated PRs to resolve these issues.

## Docstring / Function Style Guide

### Descriptors
Type hinted using python 3.8 `typing` module should be present throughout your code. Methods that return `self` should return the
class itself which c an be doin by importing
```python
from future import __annotations__
```
at the top of the mopdule.

### Documentation
Docstrings should be using Google's Napoleon docstring format with the following caveats:

* A short descriptive line at the top of the docstring explaining the high level utility of the function
* The following sections, only with the listed criteria
    * Args: No types in the parameters because the function is already type hinted.
    * Returns: No Type hinting as the descriptor has this
    * Examples: This should be a valid doctest that demonstrates the function working

#### Example
**Bad Example**
```python
def func(x):
    {"result": x**2}
```
**Good Example**
```python
from typing import Dict

def func(x: int) -> Dict[str, int]:
    """
    Return ``x**2`` in a JSON result

    Args:
        x: integer value to square

    Example:
        >>> func(2)
        {'result': 4}

    Returns:
        A dictionary like ``{"result": x**2}``
    """
    return {"result": x**2}
```

In short functions like this it is fine to ignore the doctest and the returns, instead giving a simpler docstring in accordance with PEP8

**Good Example 2**
```python
from typing import Dict

def func(x: int) -> Dict[str, int]:
    """
    Return the square of ``x`` as a dict like ``{"result": x**2}``
    """
    return {"result": x**2}
```

### Future Alignment: Sphinx Support (optional)

*If you are familiar with Sphinx language it is highly recommended to use sphinx syntax in docstrings to align witth future documentation plans.*
