# Instructions
# Bob is a lackadaisical teenager. In conversation, his responses are very limited.
# Bob answers 'Sure.' if you ask him a question, such as "How are you?".
# He answers 'Whoa, chill out!' if you YELL AT HIM (in all capitals).
# He answers 'Calm down, I know what I'm doing!' if you yell a question at him.
# He says 'Fine. Be that way!' if you address him without actually saying anything.
# He answers 'Whatever.' to anything else.
# Bob's conversational partner is a purist when it comes to written communication and always follows normal rules regarding sentence punctuation in English.

import strutils

proc hey*(sentence: string = ""): string =
  if len(sentence.strip) == 0:
    return "Fine. Be that way!"
  elif sentence.contains({'A'..'Z'}) and (not sentence.contains({'a'..'z'}) and sentence.endsWith("?")):
    return "Calm down, I know what I'm doing!"
  elif sentence.contains({'A'..'Z'}) and not sentence.contains({'a'..'z'}):
    return "Whoa, chill out!"
  elif sentence.strip(trailing = true).endsWith("?"):
    return "Sure."
  else:
    return "Whatever."