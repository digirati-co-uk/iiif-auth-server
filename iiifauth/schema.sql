drop table if exists tokens;
create table tokens (
  token text not null,
  cookiekey text not null,
  origin text not null
);